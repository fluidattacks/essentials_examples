package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// --- Vulnerable Cases ---

// Source: r.URL.Query().Get -> Sink: db.Query() via fmt.Sprintf
func vulnerableHandlerSprintf(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// VULNERABLE: Query built using string formatting.
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, _ := db.Query(query)
	defer rows.Close()
}

// Source: r.FormValue -> Sink: db.Exec() via string concatenation
func vulnerableHandlerConcatenation(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	userID := r.FormValue("id")
	// VULNERABLE: Query built using string concatenation.
	query := "UPDATE users SET email = '" + email + "' WHERE id = " + userID
	db.Exec(query)
}

// Source: r.Header.Get -> Sink: db.QueryRow() via fmt.Sprintf
func vulnerableHandlerFromHeader(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	// VULNERABLE: Query built from an HTTP header.
	query := fmt.Sprintf("SELECT user_id FROM sessions WHERE session_id = '%s'", sessionID)
	var userID int
	db.QueryRow(query).Scan(&userID)
}

// Source: r.URL.Path -> Sink: db.Query() via fmt.Sprintf
func vulnerableHandlerFromPath(w http.ResponseWriter, r *http.Request) {
	parts := r.URL.Path
	userID := parts[len(parts)-1] // Get last part of the URL path
	// VULNERABLE: Query built from a URL path segment.
	query := fmt.Sprintf("SELECT * FROM audit_log WHERE user_id = %s", userID)
	rows, _ := db.Query(query)
	defer rows.Close()
}

// Source: r.Cookie -> Sink: db.Exec() via fmt.Sprintf
func vulnerableHandlerFromCookie(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_preference")
	if err != nil {
		return
	}
	preference := cookie.Value
	// VULNERABLE: Query built from a cookie value.
	query := fmt.Sprintf("UPDATE preferences SET value = '%s' WHERE user_id = 1", preference)
	db.Exec(query)
}

func main() {
	db, _ = sql.Open("sqlite3", ":memory:")
	// ... setup database schema ...

	http.HandleFunc("/vuln/sprintf", vulnerableHandlerSprintf)
	http.HandleFunc("/vuln/concat", vulnerableHandlerConcatenation)
	http.HandleFunc("/vuln/header", vulnerableHandlerFromHeader)
	http.HandleFunc("/vuln/path/", vulnerableHandlerFromPath)
	http.HandleFunc("/vuln/cookie", vulnerableHandlerFromCookie)

	http.ListenAndServe(":8080", nil)
}
