package controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jeffthorne/tasky/auth"
	"github.com/jeffthorne/tasky/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"golang.org/x/crypto/bcrypt"
)

type Handlers struct {
	users, todos *mongo.Collection
	sessions     *auth.Sessions
}

func New(db *mongo.Database, sessions *auth.Sessions) *Handlers {
	return &Handlers{users: db.Collection("user"), todos: db.Collection("todos"), sessions: sessions}
}

func failure(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{"error": message})
}

func dbFailure(c *gin.Context) { failure(c, http.StatusServiceUnavailable, "Database unavailable") }
func notFound(c *gin.Context)  { failure(c, http.StatusNotFound, "Task not found") }

func bind(c *gin.Context, dst any) bool {
	if c.ContentType() != "application/json" || c.ShouldBindJSON(dst) != nil {
		failure(c, http.StatusBadRequest, "Invalid JSON request")
		return false
	}
	return true
}

type credentials struct {
	Name     string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) SignUp(c *gin.Context) {
	var input credentials
	if !bind(c, &input) {
		return
	}
	input.Name, input.Email = strings.TrimSpace(input.Name), strings.TrimSpace(input.Email)
	if input.Name == "" || len(input.Name) > auth.MaxDisplayNameBytes || input.Email == "" || len(input.Email) > 320 || input.Password == "" || len(input.Password) > 72 {
		failure(c, http.StatusBadRequest, "Username, email and a password of up to 72 bytes are required")
		return
	}
	ctx := c.Request.Context()
	err := h.users.FindOne(ctx, bson.M{"email": input.Email}).Err()
	if err == nil {
		failure(c, http.StatusBadRequest, "Email already registered")
		return
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		dbFailure(c)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
	if err != nil {
		failure(c, http.StatusInternalServerError, "Account creation failed")
		return
	}
	user := models.User{ID: bson.NewObjectID(), Name: input.Name, Email: input.Email, Password: string(hash)}
	_, err = h.users.InsertOne(ctx, user)
	if mongo.IsDuplicateKeyError(err) {
		failure(c, http.StatusBadRequest, "Email already registered")
		return
	}
	if err != nil {
		dbFailure(c)
		return
	}
	if err := h.sessions.Set(c.Writer, user.ID.Hex(), user.Name); err != nil {
		failure(c, http.StatusInternalServerError, "Session unavailable")
		return
	}
	c.JSON(http.StatusOK, gin.H{"InsertedID": user.ID, "user_id": user.ID})
}

func (h *Handlers) Login(c *gin.Context) {
	var input credentials
	if !bind(c, &input) {
		return
	}
	input.Email = strings.TrimSpace(input.Email)
	if input.Email == "" || input.Password == "" || len(input.Password) > 72 {
		failure(c, http.StatusBadRequest, "Email and password required")
		return
	}
	var user models.User
	err := h.users.FindOne(c.Request.Context(), bson.M{"email": input.Email}).Decode(&user)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		dbFailure(c)
		return
	}
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)) != nil {
		failure(c, http.StatusUnauthorized, "Email or password is incorrect")
		return
	}
	if err := h.sessions.Set(c.Writer, user.ID.Hex(), user.Name); err != nil {
		failure(c, http.StatusInternalServerError, "Session unavailable")
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "login successful", "user_id": user.ID})
}
