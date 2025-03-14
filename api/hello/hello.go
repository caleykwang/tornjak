package hello

import (
	"encoding/json"
	"net/http"
)

// HelloResponse defines the structure of our response.
type HelloResponse struct {
	Message string `json:"message"`
}

// HelloHandler is an HTTP handler that returns a simple greeting message.
func HelloHandler(w http.ResponseWriter, r *http.Request) {
	response := HelloResponse{
		Message: "Hello from Tornjak!",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}