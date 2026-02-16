package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCredentialsYAML = `users:
  - username: alice
    password: "alice_pass"
    auth_methods: ["md5", "scram-sha-256"]
    roles: ["admin"]
    databases: ["mydb", "analytics"]
    enabled: true
  - username: bob
    password: "bob_pass"
    auth_methods: ["md5"]
    roles: ["readonly"]
    databases: ["mydb"]
    enabled: true
  - username: disabled_user
    password: "unused"
    enabled: false
  - username: all_access
    password: "pass123"
    roles: ["superuser"]
`

func writeTestCredentials(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	err := os.WriteFile(path, []byte(content), 0o644)
	require.NoError(t, err)
	return path
}

func TestFileCredentialStore_LookupUser(t *testing.T) {
	path := writeTestCredentials(t, testCredentialsYAML)
	store, err := NewFileCredentialStore(path)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("existing user", func(t *testing.T) {
		cred, err := store.LookupUser(ctx, "alice")
		require.NoError(t, err)
		assert.Equal(t, "alice", cred.Username)
		assert.Equal(t, "alice_pass", cred.Password)
		assert.Equal(t, []string{"md5", "scram-sha-256"}, cred.AuthMethods)
		assert.Equal(t, []string{"admin"}, cred.Roles)
		assert.Equal(t, []string{"mydb", "analytics"}, cred.Databases)
		assert.True(t, cred.IsEnabled())
	})

	t.Run("user not found", func(t *testing.T) {
		_, err := store.LookupUser(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("disabled user", func(t *testing.T) {
		_, err := store.LookupUser(ctx, "disabled_user")
		assert.ErrorIs(t, err, ErrUserDisabled)
	})

	t.Run("user with no databases (all allowed)", func(t *testing.T) {
		cred, err := store.LookupUser(ctx, "all_access")
		require.NoError(t, err)
		assert.True(t, cred.IsDatabaseAllowed("anything"))
	})
}

func TestUserCredential_IsDatabaseAllowed(t *testing.T) {
	tests := []struct {
		name      string
		databases []string
		database  string
		expected  bool
	}{
		{"empty allows all", nil, "mydb", true},
		{"explicit match", []string{"mydb"}, "mydb", true},
		{"no match", []string{"mydb"}, "other", false},
		{"wildcard", []string{"*"}, "anything", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &UserCredential{Databases: tt.databases}
			assert.Equal(t, tt.expected, cred.IsDatabaseAllowed(tt.database))
		})
	}
}

func TestUserCredential_SupportsAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		methods  []string
		method   AuthType
		expected bool
	}{
		{"empty allows all", nil, AuthMD5, true},
		{"explicit match", []string{"md5"}, AuthMD5, true},
		{"no match", []string{"md5"}, AuthScramSHA256, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &UserCredential{AuthMethods: tt.methods}
			assert.Equal(t, tt.expected, cred.SupportsAuthMethod(tt.method))
		})
	}
}

func TestFileCredentialStore_Reload(t *testing.T) {
	path := writeTestCredentials(t, testCredentialsYAML)
	store, err := NewFileCredentialStore(path)
	require.NoError(t, err)

	ctx := context.Background()

	// Verify initial state.
	_, err = store.LookupUser(ctx, "alice")
	require.NoError(t, err)

	// Update the file to remove alice and add charlie.
	newContent := `users:
  - username: charlie
    password: "charlie_pass"
    roles: ["admin"]
`
	err = os.WriteFile(path, []byte(newContent), 0o644)
	require.NoError(t, err)

	// Reload.
	err = store.Reload(ctx)
	require.NoError(t, err)

	// Alice should be gone.
	_, err = store.LookupUser(ctx, "alice")
	assert.ErrorIs(t, err, ErrUserNotFound)

	// Charlie should exist.
	cred, err := store.LookupUser(ctx, "charlie")
	require.NoError(t, err)
	assert.Equal(t, "charlie_pass", cred.Password)
}

func TestFileCredentialStore_InvalidFile(t *testing.T) {
	_, err := NewFileCredentialStore("/nonexistent/path/credentials.yaml")
	assert.Error(t, err)
}
