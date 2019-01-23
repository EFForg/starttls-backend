package models

import (
	"html/template"
	"io"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

// Scan stores the result of a scan of a domain
type Scan struct {
	Domain    string               `json:"domain"`    // Input domain
	Data      checker.DomainResult `json:"scandata"`  // Scan results from starttls-checker
	Timestamp time.Time            `json:"timestamp"` // Time at which this scan was conducted
}

// WriteHTML renders a scan result as HTML.
func (s Scan) WriteHTML(w io.Writer) error {
	data := struct {
		Scan
		BaseURL string
	}{
		Scan:    s,
		BaseURL: os.Getenv("FRONTEND_WEBSITE_LINK"),
	}
	tmpl, err := template.ParseFiles("views/scan.html.tmpl")
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}
