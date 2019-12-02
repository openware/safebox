package api

import (
	"fmt"
	"net/http"
)

// InfoHandler handles API requests to mailer route
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}
