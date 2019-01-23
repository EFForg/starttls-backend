package models

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/EFForg/starttls-backend/checker"
)

func TestWriteScanHTML(t *testing.T) {
	scan := Scan{
		Data: checker.DomainResult{
			Domain: "eff.org",
		},
		Domain: "eff.org",
	}
	var html bytes.Buffer
	scan.WriteHTML(&html)
	fmt.Println(html.String())
}
