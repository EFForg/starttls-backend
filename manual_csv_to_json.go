package main

import (
	"bufio"
	"encoding/csv"
	"os"
	"strings"

	"github.com/EFForg/starttls-backend/db"
)

func readFromCSV(filename string) ([]db.DomainData, error) {
	csvFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	reader := csv.NewReader(bufio.NewReader(csvFile))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	results := []db.DomainData{}
	for _, record := range records {
		results = append(results, db.DomainData{
			Name: strings.ToLower(record[0]),
			MXs:  strings.Split(strings.ToLower(record[1]), ","),
		})
	}
	return results, nil
}
