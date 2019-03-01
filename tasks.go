package main

import (
	"encoding/csv"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

func runTask(name string) {
	switch name {
	case "update-stats":
		updateStats()
	}
}

func updateStats() {
	resp, err := http.Get("http://downloads.majestic.com/majestic_million.csv")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	domains := csv.NewReader(resp.Body)
	totals := checker.DomainTotals{
		Time:   time.Now(),
		Source: checker.MajesticMillion,
	}
	c := checker.Checker{
		Cache: checker.MakeSimpleCache(10 * time.Minute),
	}
	c.CheckCSV(domains, &totals, 2)
	log.Printf("Scans completed, got %+v\n", totals)
}
