package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
