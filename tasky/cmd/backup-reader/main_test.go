package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifiedArchive(t *testing.T) {
	const run = "20261126T100000Z-00000000-0000-0000-0000-000000000001"
	const newer = "20261127T100000Z-00000000-0000-0000-0000-000000000002"
	const content = "synthetic archive"
	dir := t.TempDir()
	assertion := filepath.Join(dir, "assertion")
	if err := os.WriteFile(assertion, []byte("local-assertion"), 0600); err != nil {
		t.Fatal(err)
	}
	corrupt := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.Method != "POST" || r.FormValue("scope") != "https://storage.azure.com/.default" || r.FormValue("client_assertion") != "local-assertion" {
				t.Error("unexpected federation request")
			}
			fmt.Fprint(w, `{"access_token":"test","token_type":"Bearer"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test" {
			t.Error("storage request missing identity")
		}
		switch r.URL.Path {
		case "/backups":
			if r.URL.Query().Get("comp") != "list" {
				t.Error("unexpected list")
			}
			if r.URL.Query().Get("marker") == "" {
				fmt.Fprintf(w, "<EnumerationResults><Blobs><Blob><Name>%s/dump.archive.gz</Name></Blob></Blobs><NextMarker>page+2</NextMarker></EnumerationResults>", newer)
			} else {
				if r.URL.Query().Get("marker") != "page+2" {
					t.Error("wrong marker")
				}
				fmt.Fprintf(w, "<EnumerationResults><Blobs><Blob><Name>%s/complete.json</Name></Blob></Blobs></EnumerationResults>", run)
			}
		case "/backups/" + run + "/complete.json":
			fmt.Fprintf(w, `{"archive":"dump.archive.gz","bytes":%d,"sha256":"%x"}`, len(content), sha256.Sum256([]byte(content)))
		case "/backups/" + run + "/dump.archive.gz":
			if corrupt {
				fmt.Fprint(w, strings.Repeat("X", len(content)))
			} else {
				fmt.Fprint(w, content)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	token, err := storageToken(context.Background(), srv.Client(), srv.URL+"/token", "id", assertion)
	if err != nil {
		t.Fatal(err)
	}
	client := blobs{srv.Client(), srv.URL + "/backups", token}
	var result bytes.Buffer
	if err = client.verify(context.Background(), dir, &result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.String(), content) || !strings.Contains(result.String(), fmt.Sprintf("%x", sha256.Sum256([]byte(content)))) {
		t.Fatal("unexpected evidence")
	}
	corrupt = true
	if err = client.verify(context.Background(), dir, &result); err == nil {
		t.Fatal("accepted corrupted archive")
	}
	data, err := os.ReadFile(filepath.Join(dir, archiveName))
	if err != nil || string(data) != content {
		t.Fatal("previous verified archive was lost")
	}
}

func TestStorageCannotDialUnapprovedDestinations(t *testing.T) {
	transport := privateTransport("localhost")
	for _, target := range []string{"localhost:443", "unexpected.invalid:443", "localhost:80"} {
		conn, err := transport.DialContext(context.Background(), "tcp", target)
		if conn != nil {
			conn.Close()
		}
		if err == nil {
			t.Fatalf("accepted %s", target)
		}
	}
}
