// List completed backups using the pod's workload identity and verify a private copy.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const maxArchive int64 = 64 << 20
const archiveName = "dump.archive.gz"
const heartbeat = "/tmp/reader-heartbeat"

var uuid = regexp.MustCompile("(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
var accountName = regexp.MustCompile("^stoutpost[0-9a-f]{10}$")
var privateEndpoints = netip.MustParsePrefix("10.84.2.64/27")
var runObject = regexp.MustCompile("^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/(complete[.]json|dump[.]archive[.]gz)$")

func smallBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("response too large or incomplete")
	}
	return data, nil
}

func storageToken(ctx context.Context, client *http.Client, endpoint, id, file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	assertion, err := smallBody(f, 32<<10)
	if err != nil || len(assertion) == 0 {
		return "", errors.New("identity assertion unavailable")
	}
	form := url.Values{
		"client_id": {id}, "grant_type": {"client_credentials"}, "scope": {"https://storage.azure.com/.default"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {strings.TrimSpace(string(assertion))},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("token exchange denied")
	}
	data, err := smallBody(resp.Body, 64<<10)
	var token struct {
		Access string `json:"access_token"`
		Type   string `json:"token_type"`
	}
	if err != nil || json.Unmarshal(data, &token) != nil || !strings.EqualFold(token.Type, "Bearer") || token.Access == "" {
		return "", errors.New("invalid token response")
	}
	return token.Access, nil
}

type blobs struct {
	client           *http.Client
	container, token string
}

func (b blobs) get(ctx context.Context, suffix string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.container+suffix, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("x-ms-version", "2023-11-03")
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New("storage request failed")
	}
	return resp.Body, nil
}

func (b blobs) read(ctx context.Context, suffix string, limit int64) ([]byte, error) {
	body, err := b.get(ctx, suffix)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return smallBody(body, limit)
}

func (b blobs) latest(ctx context.Context) (string, int, error) {
	latest, marker := "", ""
	count := 0
	for {
		query := url.Values{"restype": {"container"}, "comp": {"list"}, "maxresults": {"500"}}
		if marker != "" {
			query.Set("marker", marker)
		}
		data, err := b.read(ctx, "?"+query.Encode(), 2<<20)
		if err != nil {
			return "", 0, err
		}
		var page struct {
			Items []struct {
				Name string
				Size int64 `xml:"Properties>Content-Length"`
			} `xml:"Blobs>Blob"`
			Next string `xml:"NextMarker"`
		}
		if err := xml.Unmarshal(data, &page); err != nil {
			return "", 0, err
		}
		count += len(page.Items)
		if count > 999999999 {
			return "", 0, errors.New("too many objects")
		}
		for _, item := range page.Items {
			if !runObject.MatchString(item.Name) || item.Size < 0 {
				continue
			}
			if run, complete := strings.CutSuffix(item.Name, "/complete.json"); complete && run > latest {
				latest = run
			}
		}
		if page.Next == "" {
			break
		}
		if marker == page.Next {
			return "", 0, errors.New("invalid continuation")
		}
		marker = page.Next
	}
	if latest == "" {
		return "", 0, errors.New("no completed backup")
	}
	return latest, count, nil
}

func (b blobs) verify(ctx context.Context, dir string, out io.Writer) error {
	run, count, err := b.latest(ctx)
	if err != nil {
		return err
	}
	data, err := b.read(ctx, "/"+run+"/complete.json", 4096)
	if err != nil {
		return err
	}
	var receipt struct {
		Archive, SHA256 string
		Bytes           int64
	}
	if json.Unmarshal(data, &receipt) != nil || receipt.Archive != archiveName || receipt.Bytes <= 0 || receipt.Bytes > maxArchive || len(receipt.SHA256) != 64 {
		return errors.New("invalid completion record")
	}
	// Record the peer actually selected for the archive GET, including a reused TLS connection.
	var peer atomic.Pointer[net.TCPAddr]
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		addr, _ := info.Conn.RemoteAddr().(*net.TCPAddr)
		peer.Store(addr)
	}}
	body, err := b.get(httptrace.WithClientTrace(ctx, trace), "/"+run+"/"+archiveName)
	if err != nil {
		return err
	}
	defer body.Close()
	temp, err := os.CreateTemp(dir, ".backup-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(body, receipt.Bytes+1))
	closeErr := temp.Close()
	sum := hex.EncodeToString(hash.Sum(nil))
	if copyErr != nil || closeErr != nil || n != receipt.Bytes || sum != receipt.SHA256 {
		return errors.New("backup verification failed")
	}
	addr := peer.Load()
	if addr == nil {
		return errors.New("missing storage peer")
	}
	if err = os.Rename(temp.Name(), filepath.Join(dir, archiveName)); err != nil {
		return err
	}
	fmt.Fprintf(out, "objects %d newest %s/%s sha256 %s endpoint %s\n", count, run, archiveName, sum, addr.IP)
	return nil
}

// Keep the ordinary TLS hostname but connect Blob requests only to the resolved
// private-endpoint subnet. An accidental public DNS answer fails closed.
func privateTransport(blobHost string) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" {
				return nil, errors.New("unexpected destination")
			}
			if host == "login.microsoftonline.com" {
				return dialer.DialContext(ctx, network, address)
			}
			if host != blobHost {
				return nil, errors.New("unexpected storage hostname")
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !privateEndpoints.Contains(ip.Unmap()) {
					return nil, errors.New("public Blob DNS answer")
				}
			}
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, errors.New("private endpoint unavailable")
		},
	}
}

func once(ctx context.Context) error {
	tenant, id, account := os.Getenv("AZURE_TENANT_ID"), os.Getenv("AZURE_CLIENT_ID"), os.Getenv("BACKUP_ACCOUNT")
	if !uuid.MatchString(tenant) || !uuid.MatchString(id) || !accountName.MatchString(account) {
		return errors.New("invalid workload configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	host := account + ".blob.core.windows.net"
	client := &http.Client{Transport: privateTransport(host),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	token, err := storageToken(ctx, client, "https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token", id, os.Getenv("AZURE_FEDERATED_TOKEN_FILE"))
	if err != nil {
		return err
	}
	return (blobs{client, "https://" + host + "/backups", token}).verify(ctx, "/tmp", os.Stdout)
}

func recent(path string, age time.Duration) bool {
	s, err := os.Stat(path)
	return err == nil && s.Mode().IsRegular() && time.Since(s.ModTime()) < age
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if len(os.Args) == 1 {
		if once(ctx) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--live":
		if !recent(heartbeat, 3*time.Minute) {
			os.Exit(1)
		}
	case "--ready":
		if !recent(filepath.Join("/tmp", archiveName), 70*time.Minute) {
			os.Exit(1)
		}
	case "--serve":
		var next time.Time
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			if err := os.WriteFile(heartbeat, []byte("ok\n"), 0600); err != nil {
				os.Exit(1)
			}
			if !time.Now().Before(next) && once(ctx) == nil {
				next = time.Now().Add(time.Hour)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	default:
		os.Exit(2)
	}
}
