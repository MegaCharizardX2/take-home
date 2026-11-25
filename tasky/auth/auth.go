package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const sessionDuration = 5 * time.Minute

// MaxDisplayNameBytes bounds the optional cookie claim, including for legacy accounts.
const MaxDisplayNameBytes = 128

type Claims struct {
	// The original Tasky cookie uses "username" for the user's hexadecimal ID.
	UserID      string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	jwt.RegisteredClaims
}

type Sessions struct{ key []byte }

func New(key string) (*Sessions, error) {
	if len(key) < 32 {
		return nil, errors.New("SECRET_KEY must contain at least 32 bytes")
	}
	return &Sessions{key: []byte(key)}, nil
}

func (s *Sessions) Set(w http.ResponseWriter, id, displayName string) error {
	if len(displayName) > MaxDisplayNameBytes {
		displayName = ""
	}
	expiry := time.Now().Add(sessionDuration)
	claims := Claims{
		UserID: id, DisplayName: displayName,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiry)},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.key)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: "token", Value: token, Path: "/", Expires: expiry,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Sessions) verify(r *http.Request) (*Claims, int) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, http.StatusUnauthorized
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(*jwt.Token) (any, error) { return s.key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return nil, http.StatusBadRequest
	}
	if err != nil || !token.Valid {
		return nil, http.StatusUnauthorized
	}
	id, err := bson.ObjectIDFromHex(claims.UserID)
	if err != nil || id.IsZero() {
		return nil, http.StatusUnauthorized
	}
	return claims, http.StatusOK
}

func (s *Sessions) Require(html bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, status := s.verify(c.Request)
		if status != http.StatusOK {
			if html && status == http.StatusUnauthorized {
				c.Redirect(http.StatusSeeOther, "/")
				c.Abort()
				return
			}
			c.AbortWithStatusJSON(status, gin.H{"error": "Invalid or missing session"})
			return
		}
		if target := c.Param("userid"); target != "" && target != claims.UserID {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Task not found"})
			return
		}
		if time.Until(claims.ExpiresAt.Time) < 30*time.Second {
			if err := s.Set(c.Writer, claims.UserID, claims.DisplayName); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Session unavailable"})
				return
			}
		}
		c.Set("session", claims)
		c.Next()
	}
}
