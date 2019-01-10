package models

import (
	"html/template"
	"net/http"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

type Scan struct {
	Domain    string               `json:"domain"`    // Input domain
	Data      checker.DomainResult `json:"scandata"`  // Scan results from starttls-checker
	Timestamp time.Time            `json:"timestamp"` // Time at which this scan was conducted
}

func (s Scan) WriteHTML(w http.ResponseWriter) error {
	tmpl := template.Must(template.ParseFiles("views/scan.html.tmpl"))
	return tmpl.Execute(w, s)
}
