package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestSessionValidation(t *testing.T) {
	for _, key := range []string{"", "short"} {
		if _, err := New(key); err == nil {
			t.Fatal("weak signing key accepted")
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := New(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	id := bson.NewObjectID().Hex()
	for _, tc := range []struct {
		name       string
		alg        *jwt.SigningMethodHMAC
		exp        *jwt.NumericDate
		signingKey []byte
		want       int
	}{
		{"valid", jwt.SigningMethodHS256, jwt.NewNumericDate(time.Now().Add(time.Minute)), s.key, 200},
		{"expired", jwt.SigningMethodHS256, jwt.NewNumericDate(time.Now().Add(-time.Minute)), s.key, 401},
		{"missing expiry", jwt.SigningMethodHS256, nil, s.key, 401},
		{"other algorithm", jwt.SigningMethodHS384, jwt.NewNumericDate(time.Now().Add(time.Minute)), s.key, 401},
		{"empty session key", jwt.SigningMethodHS256, jwt.NewNumericDate(time.Now().Add(time.Minute)), []byte{}, 401},
		{"other session key", jwt.SigningMethodHS256, jwt.NewNumericDate(time.Now().Add(time.Minute)), key, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := Claims{UserID: id, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: tc.exp}}
			value, err := jwt.NewWithClaims(tc.alg, claims).SignedString(tc.signingKey)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/", nil)
			req.AddCookie(&http.Cookie{Name: "token", Value: value})
			got, status := s.verify(req)
			if status != tc.want || (status == 200 && got.UserID != id) {
				t.Errorf("got %d, want %d", status, tc.want)
			}
		})
	}
}

func TestSlidingSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sessions, err := New(rand.Text() + rand.Text())
		if err != nil {
			t.Fatal(err)
		}
		id := bson.NewObjectID().Hex()
		router := gin.New()
		ok := func(c *gin.Context) { c.Status(http.StatusNoContent) }
		router.GET("/api", sessions.Require(false), ok)
		router.GET("/page", sessions.Require(true), ok)
		get := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			return w
		}
		issuedCookie := func(w *httptest.ResponseRecorder) *http.Cookie {
			t.Helper()
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected one session cookie, got %d", len(cookies))
			}
			cookie := cookies[0]
			req := httptest.NewRequest(http.MethodGet, "/api", nil)
			req.AddCookie(cookie)
			claims, status := sessions.verify(req)
			if status != http.StatusOK || claims.UserID != id || !claims.ExpiresAt.Time.Equal(cookie.Expires) {
				t.Fatal("cookie and signed session must have the same owner and expiry")
			}
			if !cookie.Expires.Equal(time.Now().Add(30*time.Minute)) ||
				!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("expected a protected session cookie valid for 30 minutes")
			}
			return cookie
		}

		login := httptest.NewRecorder()
		if err := sessions.Set(login, id, "test"); err != nil {
			t.Fatal(err)
		}
		original := issuedCookie(login)
		for _, advance := range []time.Duration{10 * time.Minute, 5 * time.Minute} {
			time.Sleep(advance) // virtual clock: 20 minutes left, then exactly 15
			w := get("/api", original)
			if w.Code != http.StatusNoContent || w.Header().Get("Set-Cookie") != "" {
				t.Fatalf("session with %s left should be accepted without renewal", time.Until(original.Expires))
			}
		}
		time.Sleep(5 * time.Minute) // 10 minutes left
		w := get("/api", original)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected a successful request during renewal, got %d", w.Code)
		}
		renewed := issuedCookie(w)
		time.Sleep(30 * time.Minute) // idle until the renewed session expires
		api, page := get("/api", renewed), get("/page", renewed)
		if api.Code != http.StatusUnauthorized || page.Code != http.StatusSeeOther || page.Header().Get("Location") != "/" {
			t.Fatalf("unexpected expired session responses: API %d, HTML %d", api.Code, page.Code)
		}
		if len(api.Result().Cookies()) != 0 || len(page.Result().Cookies()) != 0 {
			t.Fatal("expired sessions must not be renewed")
		}
	})
}

func TestLegacyDisplayNameSize(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sessions, err := New(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	id := bson.NewObjectID().Hex()
	for _, size := range []int{MaxDisplayNameBytes, MaxDisplayNameBytes + 1, 8192} {
		name := strings.Repeat("x", size)
		w := httptest.NewRecorder()
		if err := sessions.Set(w, id, name); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(w.Result().Cookies()[0])
		claims, status := sessions.verify(req)
		if status != http.StatusOK || claims.UserID != id {
			t.Fatalf("account with a %d-byte name lost its session", size)
		}
		if size > MaxDisplayNameBytes {
			name = ""
		}
		if claims.DisplayName != name {
			t.Fatalf("unexpected display-name claim for %d-byte input", size)
		}
	}
}
