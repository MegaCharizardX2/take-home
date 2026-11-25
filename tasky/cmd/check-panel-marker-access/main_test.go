package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMarkerDecision(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test" {
				t.Error("unexpected review request")
			}
			var req struct {
				Spec struct {
					Attributes map[string]string `json:"resourceAttributes"`
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				http.Error(w, "invalid test request", http.StatusBadRequest)
				return
			}
			a := req.Spec.Attributes
			if a["namespace"] != "wiz-evidence" || a["resource"] != "configmaps" || a["name"] != "panel-marker" || a["verb"] != "get" || a["group"] != "" {
				t.Error("review scope changed")
			}
			fmt.Fprintf(w, `{"status":{"allowed":%t}}`, allowed)
		}))
		got, err := decision(server.Client(), server.URL, "test")
		server.Close()
		if err != nil || got != allowed {
			t.Fatal("incorrect review decision")
		}
	}
}
