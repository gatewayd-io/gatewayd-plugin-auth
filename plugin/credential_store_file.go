package plugin

import (
	"context"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// credentialsFile is the top-level structure of the YAML credentials file.
type credentialsFile struct {
	Users []UserCredential `yaml:"users"`
}

// FileCredentialStore implements CredentialStore backed by a YAML file.
type FileCredentialStore struct {
	mu       sync.RWMutex
	filePath string
	users    map[string]*UserCredential // keyed by username
}

// NewFileCredentialStore creates a FileCredentialStore and loads credentials from the given path.
func NewFileCredentialStore(filePath string) (*FileCredentialStore, error) {
	store := &FileCredentialStore{
		filePath: filePath,
		users:    make(map[string]*UserCredential),
	}
	if err := store.Reload(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load credentials from %s: %w", filePath, err)
	}
	return store, nil
}

// LookupUser returns the credential for the given username.
func (s *FileCredentialStore) LookupUser(_ context.Context, username string) (*UserCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	if !cred.IsEnabled() {
		return nil, ErrUserDisabled
	}
	return cred, nil
}

// Reload re-reads the YAML file and replaces the in-memory user map.
func (s *FileCredentialStore) Reload(_ context.Context) error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("reading credentials file: %w", err)
	}

	var creds credentialsFile
	if err := yaml.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("parsing credentials file: %w", err)
	}

	newUsers := make(map[string]*UserCredential, len(creds.Users))
	for i := range creds.Users {
		u := &creds.Users[i]
		if u.Username == "" {
			continue
		}
		newUsers[u.Username] = u
	}

	s.mu.Lock()
	s.users = newUsers
	s.mu.Unlock()

	return nil
}
