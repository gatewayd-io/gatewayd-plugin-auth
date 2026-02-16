package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCasbinFiles(t *testing.T) (modelPath, policyPath string) {
	t.Helper()
	dir := t.TempDir()

	model := `[request_definition]
r = sub, db, obj, act

[policy_definition]
p = sub, db, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && (r.db == p.db || p.db == "*") && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*")
`
	policy := `p, admin, *, *, *
p, readonly, *, *, read
p, readwrite, *, *, read
p, readwrite, *, *, write

g, alice, admin
g, bob, readonly
g, charlie, readwrite
`

	modelPath = filepath.Join(dir, "model.conf")
	policyPath = filepath.Join(dir, "policy.csv")
	require.NoError(t, os.WriteFile(modelPath, []byte(model), 0o644))
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o644))
	return modelPath, policyPath
}

func TestAuthorizer_AdminAllowsAll(t *testing.T) {
	modelPath, policyPath := setupCasbinFiles(t)
	logger := hclog.NewNullLogger()

	authorizer, err := NewAuthorizer(modelPath, policyPath, logger)
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	allowed, err := authorizer.Authorize("alice", "mydb", "SELECT * FROM users")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = authorizer.Authorize("alice", "mydb", "DROP TABLE users")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_ReadonlyCanOnlyRead(t *testing.T) {
	modelPath, policyPath := setupCasbinFiles(t)
	logger := hclog.NewNullLogger()

	authorizer, err := NewAuthorizer(modelPath, policyPath, logger)
	require.NoError(t, err)

	allowed, err := authorizer.Authorize("bob", "mydb", "SELECT * FROM users")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = authorizer.Authorize("bob", "mydb", "INSERT INTO users (name) VALUES ('test')")
	require.NoError(t, err)
	assert.False(t, allowed)

	allowed, err = authorizer.Authorize("bob", "mydb", "DELETE FROM users WHERE id = 1")
	require.NoError(t, err)
	assert.False(t, allowed)

	allowed, err = authorizer.Authorize("bob", "mydb", "DROP TABLE users")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_ReadwriteCanReadAndWrite(t *testing.T) {
	modelPath, policyPath := setupCasbinFiles(t)
	logger := hclog.NewNullLogger()

	authorizer, err := NewAuthorizer(modelPath, policyPath, logger)
	require.NoError(t, err)

	allowed, err := authorizer.Authorize("charlie", "mydb", "SELECT * FROM users")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = authorizer.Authorize("charlie", "mydb", "INSERT INTO users (name) VALUES ('test')")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = authorizer.Authorize("charlie", "mydb", "UPDATE users SET name = 'test' WHERE id = 1")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Admin operations should be denied.
	allowed, err = authorizer.Authorize("charlie", "mydb", "DROP TABLE users")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_NilWhenPathsEmpty(t *testing.T) {
	logger := hclog.NewNullLogger()
	authorizer, err := NewAuthorizer("", "", logger)
	require.NoError(t, err)
	assert.Nil(t, authorizer)
}

func TestSqlAction(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{"SELECT * FROM users", "read"},
		{"select * from users", "read"},
		{"INSERT INTO users VALUES (1)", "write"},
		{"UPDATE users SET name='x'", "write"},
		{"DELETE FROM users", "write"},
		{"CREATE TABLE users (id INT)", "admin"},
		{"DROP TABLE users", "admin"},
		{"ALTER TABLE users ADD COLUMN name TEXT", "admin"},
		{"TRUNCATE users", "admin"},
		{"GRANT SELECT ON users TO bob", "admin"},
		{"REVOKE SELECT ON users FROM bob", "admin"},
		{"EXPLAIN SELECT 1", "read"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			assert.Equal(t, tt.expected, sqlAction(tt.query))
		})
	}
}
