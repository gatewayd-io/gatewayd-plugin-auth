package plugin

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	"github.com/hashicorp/go-hclog"
)

// Authorizer performs Casbin-based RBAC authorization on SQL queries.
type Authorizer struct {
	enforcer *casbin.Enforcer
	logger   hclog.Logger
}

// NewAuthorizer creates a new Authorizer with the given Casbin model and policy files.
// Returns nil if either path is empty (authorization disabled).
func NewAuthorizer(modelPath, policyPath string, logger hclog.Logger) (*Authorizer, error) {
	if modelPath == "" || policyPath == "" {
		return nil, nil //nolint:nilnil
	}

	enforcer, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, fmt.Errorf("creating casbin enforcer: %w", err)
	}

	return &Authorizer{
		enforcer: enforcer,
		logger:   logger,
	}, nil
}

// Authorize checks if the given user can execute the given SQL query on the given database.
// It parses the query to extract tables and maps the SQL operation to a Casbin action.
func (a *Authorizer) Authorize(username, database, query string) (bool, error) {
	if a.enforcer == nil {
		return true, nil
	}

	// Extract tables from the query.
	tables, err := postgres.GetTablesFromQuery(query)
	if err != nil {
		// If we can't parse the query, allow it through (fail open).
		a.logger.Debug("Failed to parse query for authorization", "error", err, "query", query)
		return true, nil
	}

	// Determine the action from the SQL operation.
	action := sqlAction(query)

	// Check authorization for each table.
	for _, table := range tables {
		allowed, err := a.enforcer.Enforce(username, database, table, action)
		if err != nil {
			return false, fmt.Errorf("casbin enforce error: %w", err)
		}
		if !allowed {
			a.logger.Debug("Authorization denied",
				"user", username,
				"database", database,
				"table", table,
				"action", action)
			return false, nil
		}
	}

	return true, nil
}

// ReloadPolicy reloads the Casbin policy from the backing store.
func (a *Authorizer) ReloadPolicy() error {
	if a.enforcer == nil {
		return nil
	}
	return a.enforcer.LoadPolicy()
}

// Casbin action constants used in authorization policy evaluation.
const (
	ActionRead  = "read"
	ActionWrite = "write"
	ActionAdmin = "admin"
)

// sqlAction maps the first SQL keyword to a Casbin action.
func sqlAction(query string) string {
	normalized := strings.TrimSpace(strings.ToUpper(query))

	switch {
	case strings.HasPrefix(normalized, "SELECT"):
		return ActionRead
	case strings.HasPrefix(normalized, "INSERT"):
		return ActionWrite
	case strings.HasPrefix(normalized, "UPDATE"):
		return ActionWrite
	case strings.HasPrefix(normalized, "DELETE"):
		return ActionWrite
	case strings.HasPrefix(normalized, "CREATE"):
		return ActionAdmin
	case strings.HasPrefix(normalized, "DROP"):
		return ActionAdmin
	case strings.HasPrefix(normalized, "ALTER"):
		return ActionAdmin
	case strings.HasPrefix(normalized, "TRUNCATE"):
		return ActionAdmin
	case strings.HasPrefix(normalized, "GRANT"):
		return ActionAdmin
	case strings.HasPrefix(normalized, "REVOKE"):
		return ActionAdmin
	default:
		return ActionRead
	}
}
