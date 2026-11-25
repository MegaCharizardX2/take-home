// The panel compares the same workload identity before and after binding removal.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const reviewURL = "https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
const serviceAccount = "/var/run/secrets/kubernetes.io/serviceaccount/"
const review = `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"wiz-evidence","verb":"get","group":"","resource":"configmaps","name":"panel-marker"}}}`

func decision(client *http.Client, endpoint, token string) (bool, error) {
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(review))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return false, errors.New("review unavailable")
	}
	var result struct {
		Status struct {
			Allowed         *bool
			EvaluationError string
		}
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result)
	if err != nil || result.Status.Allowed == nil || result.Status.EvaluationError != "" {
		return false, errors.New("incomplete review")
	}
	return *result.Status.Allowed, nil
}

func main() {
	token, err := os.ReadFile(serviceAccount + "token")
	if err != nil || strings.TrimSpace(string(token)) == "" {
		os.Exit(2)
	}
	ca, err := os.ReadFile(serviceAccount + "ca.crt")
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		os.Exit(2)
	}
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	allowed, err := decision(client, reviewURL, strings.TrimSpace(string(token)))
	if err != nil {
		os.Exit(2)
	}
	if allowed {
		fmt.Println("allowed")
	} else {
		fmt.Println("denied")
	}
}
