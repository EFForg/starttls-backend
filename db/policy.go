package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/EFForg/starttls-backend/models"
)

func (db SQLDatabase) queryDomain(sqlQuery string, args ...interface{}) (models.Domain, error) {
	query := fmt.Sprintf(sqlQuery, "domain, email, data, status, last_updated, queue_weeks")
	data := models.Domain{}
	var rawMXs string
	err := db.conn.QueryRow(query, args...).Scan(
		&data.Name, &data.Email, &rawMXs, &data.State, &data.LastUpdated, &data.QueueWeeks)
	data.MXs = strings.Split(rawMXs, ",")
	if len(rawMXs) == 0 {
		data.MXs = []string{}
	}
	return data, err
}

func (db SQLDatabase) queryDomainsWhere(condition string, args ...interface{}) ([]models.Domain, error) {
	query := fmt.Sprintf("SELECT domain, email, data, status, last_updated, queue_weeks FROM domains WHERE %s", condition)
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	domains := []models.Domain{}
	for rows.Next() {
		var domain models.Domain
		var rawMXs string
		if err := rows.Scan(&domain.Name, &domain.Email, &rawMXs, &domain.State, &domain.LastUpdated, &domain.QueueWeeks); err != nil {
			return nil, err
		}
		domain.MXs = strings.Split(rawMXs, ",")
		domains = append(domains, domain)
	}
	return domains, nil
}

// =============== models.DomainStore impl ===============

// PutDomain inserts a particular domain into the database. If the domain does
// not yet exist in the database, we initialize it with StateUnconfirmed
// If there is already a domain in the database with StateUnconfirmed, performs
// an update of the fields.
func (db *SQLDatabase) PutDomain(domain models.Domain) error {
	_, err := db.conn.Exec("INSERT INTO domains(domain, email, data, status, queue_weeks, mta_sts) "+
		"VALUES($1, $2, $3, $4, $5, $6) "+
		"ON CONFLICT ON CONSTRAINT domains_pkey DO UPDATE SET email=$2, data=$3, queue_weeks=$5",
		domain.Name, domain.Email, strings.Join(domain.MXs[:], ","),
		models.StateUnconfirmed, domain.QueueWeeks, domain.MTASTS)
	return err
}

// GetDomain retrieves the status and information associated with a particular
// mailserver domain.
func (db SQLDatabase) GetDomain(domain string, state models.DomainState) (models.Domain, error) {
	return db.queryDomain("SELECT %s FROM domains WHERE domain=$1 AND status=$2", domain, state)
}

// GetDomains retrieves all the domains which match a particular state,
// that are not in MTA_STS mode
func (db SQLDatabase) GetDomains(state models.DomainState) ([]models.Domain, error) {
	return db.queryDomainsWhere("status=$1", state)
}

// GetMTASTSDomains retrieves domains which wish their policy to be queued with their MTASTS.
func (db SQLDatabase) GetMTASTSDomains() ([]models.Domain, error) {
	return db.queryDomainsWhere("mta_sts=TRUE")
}

// SetStatus sets the status of a particular domain object to |state|.
func (db SQLDatabase) SetStatus(domain string, state models.DomainState) error {
	var testingStart time.Time
	if state == models.StateTesting {
		testingStart = time.Now()
	}
	_, err := db.conn.Exec("UPDATE domains SET status = $1, testing_start = $2 WHERE domain=$3",
		state, testingStart, domain)
	return err
}

// RemoveDomain removes a particular domain and returns it.
func (db SQLDatabase) RemoveDomain(domain string, state models.DomainState) (models.Domain, error) {
	return db.queryDomain("DELETE FROM domains WHERE domain=$1 AND status=$2 RETURNING %s")
}

// DomainsToValidate [interface Validator] retrieves domains from the
// DB whose policies should be validated.
func (db SQLDatabase) DomainsToValidate() ([]string, error) {
	domains := []string{}
	data, err := db.GetDomains(models.StateTesting)
	if err != nil {
		return domains, err
	}
	for _, domainInfo := range data {
		domains = append(domains, domainInfo.Name)
	}
	return domains, nil
}

// HostnamesForDomain [interface Validator] retrieves the hostname policy for
// a particular domain.
func (db SQLDatabase) HostnamesForDomain(domain string) ([]string, error) {
	data, err := db.GetDomain(domain, models.StateEnforce)
	if err != nil {
		data, err = db.GetDomain(domain, models.StateTesting)
	}
	if err != nil {
		return []string{}, err
	}
	return data.MXs, nil
}
