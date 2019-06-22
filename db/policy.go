package db

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/policy"
)

// PolicyDB is a database of PolicySubmissions.
type PolicyDB struct {
	tableName string
	conn      *sql.DB
	strict    bool
}

func (p *PolicyDB) formQuery(query string) string {
	return fmt.Sprintf(query, p.tableName, "domain, email, mta_sts, mxs, mode")
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func (p *PolicyDB) scanPolicy(result scanner) (models.PolicySubmission, error) {
	data := models.PolicySubmission{Policy: new(policy.TLSPolicy)}
	var rawMXs string
	err := result.Scan(
		&data.Name, &data.Email,
		&data.MTASTS, &rawMXs, &data.Policy.Mode)
	data.Policy.MXs = strings.Split(rawMXs, ",")
	return data, err
}

// GetPolicies returns a list of policy submissions that match
// the mtasts status given.
func (p *PolicyDB) GetPolicies(mtasts bool) ([]models.PolicySubmission, error) {
	rows, err := p.conn.Query(p.formQuery(
		"SELECT %[2]s FROM %[1]s WHERE mta_sts=$1"), mtasts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := []models.PolicySubmission{}
	for rows.Next() {
		policy, err := p.scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// GetPolicy returns the policy submission for the given domain.
// Returns the submission (if found), whether it was found, and any errors encountered.
func (p *PolicyDB) GetPolicy(domainName string) (policy models.PolicySubmission, ok bool, err error) {
	row := p.conn.QueryRow(p.formQuery(
		"SELECT %[2]s FROM %[1]s WHERE domain=$1"), domainName)
	result, err := p.scanPolicy(row)
	if err == sql.ErrNoRows {
		return result, false, nil
	}
	return result, true, err
}

// RemovePolicy removes the policy submission with the given domain from
// the database.
func (p *PolicyDB) RemovePolicy(domainName string) (models.PolicySubmission, error) {
	row := p.conn.QueryRow(p.formQuery(
		"DELETE FROM %[1]s WHERE domain=$1 RETURNING %[2]s"), domainName)
	return p.scanPolicy(row)
}

// PutOrUpdatePolicy upserts the given policy into the data store, if
// CanUpdate passes.
func (p *PolicyDB) PutOrUpdatePolicy(ps *models.PolicySubmission) error {
	if p.strict && !ps.CanUpdate(p) {
		return fmt.Errorf("can't update policy in restricted table")
	}
	if p.strict && ps.Policy == nil {
		return fmt.Errorf("can't degrade policy in restricted table")
	}
	if ps.Policy == nil {
		ps.Policy = &policy.TLSPolicy{MXs: []string{}, Mode: ""}
	}
	_, err := p.conn.Exec(p.formQuery(
		"INSERT INTO %[1]s(%[2]s) VALUES($1, $2, $3, $4, $5) "+
			"ON CONFLICT (domain) DO UPDATE SET "+
			"email=$2, mta_sts=$3, mxs=$4, mode=$5"),
		ps.Name, ps.Email, ps.MTASTS,
		strings.Join(ps.Policy.MXs[:], ","), ps.Policy.Mode)
	return err
}

// DomainsToValidate [interface Validator] retrieves domains from the
// DB whose policies should be validated-- all Pending policies.
func (p *PolicyDB) DomainsToValidate() ([]string, error) {
	domains := []string{}
	data, err := p.GetPolicies(true)
	if err != nil {
		return domains, err
	}
	for _, domainInfo := range data {
		domains = append(domains, domainInfo.Name)
	}
	return domains, nil
}

// HostnamesForDomain [interface Validator] retrieves the hostname policy for
// a particular domain in Pending.
func (db SQLDatabase) HostnamesForDomain(domain string) ([]string, error) {
	data, ok, err := db.PendingPolicies.GetPolicy(domain)
	if !ok {
		err = fmt.Errorf("domain %s not in database", domain)
	}
	if err != nil {
		return []string{}, err
	}
	return data.Policy.MXs, nil
}
