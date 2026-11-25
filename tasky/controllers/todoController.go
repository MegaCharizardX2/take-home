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
)

func session(c *gin.Context) *auth.Claims { return c.MustGet("session").(*auth.Claims) }

func TodoPage(c *gin.Context) { c.HTML(http.StatusOK, "todo.html", session(c)) }

func taskFilter(c *gin.Context) (bson.M, bool) {
	id, err := bson.ObjectIDFromHex(c.Param("id"))
	if err != nil || id.IsZero() {
		notFound(c)
		return nil, false
	}
	return bson.M{"_id": id, "userid": session(c).UserID}, true
}

func (h *Handlers) GetTodo(c *gin.Context) {
	filter, ok := taskFilter(c)
	if !ok {
		return
	}
	var todo models.Todo
	err := h.todos.FindOne(c.Request.Context(), filter).Decode(&todo)
	if errors.Is(err, mongo.ErrNoDocuments) {
		notFound(c)
		return
	}
	if err != nil {
		dbFailure(c)
		return
	}
	c.JSON(http.StatusOK, todo)
}

func (h *Handlers) GetTodos(c *gin.Context) {
	ctx := c.Request.Context()
	cursor, err := h.todos.Find(ctx, bson.M{"userid": session(c).UserID})
	if err != nil {
		dbFailure(c)
		return
	}
	todos := []models.Todo{}
	if err := cursor.All(ctx, &todos); err != nil {
		dbFailure(c)
		return
	}
	c.JSON(http.StatusOK, todos)
}

func readTodo(c *gin.Context) (models.Todo, bool) {
	var todo models.Todo
	if !bind(c, &todo) {
		return todo, false
	}
	owner := session(c).UserID
	if todo.UserID != "" && todo.UserID != owner {
		notFound(c)
		return todo, false
	}
	todo.UserID = owner
	todo.Name = strings.TrimSpace(todo.Name)
	if todo.Name == "" || len(todo.Name) > 4096 || (todo.Status != "pending" && todo.Status != "completed") {
		failure(c, http.StatusBadRequest, "A task name and pending or completed status are required")
		return todo, false
	}
	return todo, true
}

func (h *Handlers) AddTodo(c *gin.Context) {
	todo, ok := readTodo(c)
	if !ok {
		return
	}
	todo.ID = bson.NewObjectID()
	if _, err := h.todos.InsertOne(c.Request.Context(), todo); err != nil {
		dbFailure(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"insertedId": todo.ID})
}

func (h *Handlers) UpdateTodo(c *gin.Context) {
	todo, ok := readTodo(c)
	if !ok {
		return
	}
	if todo.ID.IsZero() {
		notFound(c)
		return
	}
	result, err := h.todos.UpdateOne(c.Request.Context(), bson.M{"_id": todo.ID, "userid": session(c).UserID}, bson.M{"$set": bson.M{"name": todo.Name, "status": todo.Status}})
	if err != nil {
		dbFailure(c)
		return
	}
	if result.MatchedCount == 0 {
		notFound(c)
		return
	}
	c.JSON(http.StatusOK, todo)
}

func (h *Handlers) DeleteTodo(c *gin.Context) {
	filter, ok := taskFilter(c)
	if !ok {
		return
	}
	result, err := h.todos.DeleteOne(c.Request.Context(), filter)
	if err != nil {
		dbFailure(c)
		return
	}
	if result.DeletedCount == 0 {
		notFound(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": "Task deleted"})
}

func (h *Handlers) ClearAll(c *gin.Context) {
	if _, err := h.todos.DeleteMany(c.Request.Context(), bson.M{"userid": session(c).UserID}); err != nil {
		dbFailure(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": "All tasks deleted"})
}
