package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeffthorne/tasky/auth"
	"github.com/jeffthorne/tasky/database"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// This router exercises the HTTP boundary without opening a database connection.
type offlineDialer struct{}

func (offlineDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("offline test")
}

func TestRouteBoundaries(t *testing.T) {
	client, err := mongo.Connect(options.Client().SetDialer(offlineDialer{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(client) })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.New(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	r := router(client.Database("test"), sessions)
	owner, other := bson.NewObjectID().Hex(), bson.NewObjectID().Hex()
	w := httptest.NewRecorder()
	if err := sessions.Set(w, owner, `A & "B" <C>`); err != nil {
		t.Fatal(err)
	}
	token := w.Result().Cookies()[0]
	if !token.HttpOnly || !token.Secure || token.SameSite != http.SameSiteLaxMode || token.Path != "/" {
		t.Fatal("session cookie lacks expected flags")
	}
	foreignBody := `{"name":"test","status":"pending","user_id":"` + other + `"}`
	for _, tc := range []struct {
		method, path, body string
		cookie             *http.Cookie
		code               int
	}{
		{"GET", "/healthz", "", nil, 200},
		{"GET", "/assets/todo.html", "", nil, 404},
		{"GET", "/todo", "", nil, 303},
		{"GET", "/todo/" + other, "", nil, 401},
		{"GET", "/todos/" + owner, "", nil, 401},
		{"POST", "/todo/" + owner, "", nil, 401},
		{"PUT", "/todo", "", nil, 401},
		{"DELETE", "/todo/" + owner + "/" + other, "", nil, 401},
		{"DELETE", "/todos/" + owner, "", nil, 401},
		{"GET", "/todos/" + owner, "", &http.Cookie{Name: "token", Value: "malformed"}, 400},
		{"GET", "/todos/" + other, "", token, 404},
		{"POST", "/todo/" + other, "", token, 404},
		{"DELETE", "/todo/" + other + "/" + owner, "", token, 404},
		{"DELETE", "/todos/" + other, "", token, 404},
		{"POST", "/todo/" + owner, foreignBody, token, 404},
		{"PUT", "/todo", foreignBody, token, 404},
		{"GET", "/todo/unknown", "", token, 404},
		{"PUT", "/todo", `{"name":"test","status":"completed"}`, token, 404},
		{"POST", "/signup", `{"username":"test","email":"test@example.invalid"}`, nil, 400},
		{"POST", "/login", `{"email":"test@example.invalid"}`, nil, 400},
		{"GET", "/todo", "", token, 200},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.code {
				t.Fatalf("got %d, want %d", w.Code, tc.code)
			}
			if !strings.HasPrefix(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
				t.Fatal("missing CSP")
			}
			if tc.path == "/healthz" && w.Body.Len() != 0 {
				t.Error("probe body should be empty")
			}
			if tc.path == "/todo" && tc.code == 200 && !strings.Contains(w.Body.String(), `A &amp; &#34;B&#34; &lt;C&gt;`) {
				t.Error("display name missing or not escaped in template")
			}
		})
	}
}
