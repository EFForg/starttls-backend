package models

import (
	"bytes"
	"fmt"
	"testing"
)

func TestWriteScanHTML(t *testing.T) {
	scan := Scan{
		Domain: "eff.org",
	}
	var html bytes.Buffer
	scan.WriteHTML(&html)
	fmt.Println(html.String())
}
