// Package main demonstrates SQL injection in Go (CWE-89).
//
// DO NOT use this code. It is an intentionally vulnerable sample for vulnforge.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// lookupUser builds a SQL query by string concatenation — vulnerable to SQLi.
func lookupUser(db *sql.DB, name string) error {
	// vulnforge-static: sql-injection
	query := "SELECT id, email FROM users WHERE name = '" + name + "'"
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

// handler reflects a query parameter back into the response — XSS (CWE-79).
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// vulnforge-static: xss
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", name)
}
