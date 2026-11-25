package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jeffthorne/tasky/auth"
	controller "github.com/jeffthorne/tasky/controllers"
	"github.com/jeffthorne/tasky/database"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func router(db *mongo.Database, sessions *auth.Sessions) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.RedirectTrailingSlash = false
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) { c.AbortWithStatus(http.StatusInternalServerError) }))
	r.Use(func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "no-store")
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	r.LoadHTMLGlob("assets/*.html")
	for _, dir := range []string{"css", "js", "img"} {
		r.Static("/assets/"+dir, "./assets/"+dir)
	}
	r.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "login.html", nil) })
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := db.Client().Ping(ctx, nil); err != nil {
			c.Status(http.StatusServiceUnavailable)
			return
		}
		c.Status(http.StatusOK)
	})
	h := controller.New(db, sessions)
	r.POST("/signup", h.SignUp)
	r.POST("/login", h.Login)
	r.GET("/todo", sessions.Require(true), controller.TodoPage)
	api := r.Group("", sessions.Require(false))
	api.GET("/todos/:userid", h.GetTodos)
	api.GET("/todo/:id", h.GetTodo)
	api.POST("/todo/:userid", h.AddTodo)
	api.PUT("/todo", h.UpdateTodo)
	api.DELETE("/todo/:userid/:id", h.DeleteTodo)
	api.DELETE("/todos/:userid", h.ClearAll)
	return r
}

func run(ctx context.Context, uri, key string) error {
	sessions, err := auth.New(key)
	if err != nil {
		return err
	}
	db, err := database.Open(ctx, uri)
	if err != nil {
		return err
	}
	defer database.Close(db.Client())
	log.Print("Connected to MongoDB")
	server := &http.Server{
		Addr: ":8080", Handler: router(db, sessions),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal("Unable to load .env")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv("MONGODB_URI"), os.Getenv("SECRET_KEY")); err != nil {
		log.Fatal(err)
	}
}
