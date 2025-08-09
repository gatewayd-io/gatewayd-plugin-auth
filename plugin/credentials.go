package plugin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cast"
)

// Credential represents a user credential
type Credential struct {
	Username    string            `json:"username"`
	Password    string            `json:"password,omitempty"`
	Salt        string            `json:"salt,omitempty"`
	Iterations  int               `json:"iterations,omitempty"`
	ServerKey   string            `json:"server_key,omitempty"`
	StoredKey   string            `json:"stored_key,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Certificate *x509.Certificate `json:"-"` // Certificate for cert auth
}

// CredentialStore interface for different credential backends
type CredentialStore interface {
	GetCredential(ctx context.Context, username string) (*Credential, error)
	ValidateCredential(ctx context.Context, username, password string) (*Credential, error)
	ValidateCertificate(ctx context.Context, cert *x509.Certificate) (*Credential, error)
	IsExpired(cred *Credential) bool
}

// EnvCredentialStore implements credential storage using environment variables
type EnvCredentialStore struct {
	logger hclog.Logger
}

// FileCredentialStore implements credential storage using JSON files
type FileCredentialStore struct {
	logger   hclog.Logger
	filePath string
}

// VaultCredentialStore implements credential storage using HashiCorp Vault
type VaultCredentialStore struct {
	logger    hclog.Logger
	address   string
	token     string
	mountPath string
	client    *http.Client
}

// NewCredentialStore creates a new credential store based on the backend type
func NewCredentialStore(backend CredentialBackend, config map[string]interface{}, logger hclog.Logger) (CredentialStore, error) {
	switch backend {
	case ENV_BACKEND:
		return &EnvCredentialStore{logger: logger}, nil
	case FILE_BACKEND:
		filePath := cast.ToString(config["file_path"])
		if filePath == "" {
			return nil, fmt.Errorf("file_path is required for file backend")
		}
		return &FileCredentialStore{
			logger:   logger,
			filePath: filePath,
		}, nil
	case VAULT_BACKEND:
		address := cast.ToString(config["address"])
		token := cast.ToString(config["token"])
		mountPath := cast.ToString(config["mount_path"])
		if address == "" || token == "" {
			return nil, fmt.Errorf("address and token are required for vault backend")
		}
		if mountPath == "" {
			mountPath = "secret"
		}
		return &VaultCredentialStore{
			logger:    logger,
			address:   address,
			token:     token,
			mountPath: mountPath,
			client: &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: cast.ToBool(config["insecure_skip_verify"])},
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported credential backend: %s", backend)
	}
}

// EnvCredentialStore implementation
func (e *EnvCredentialStore) GetCredential(ctx context.Context, username string) (*Credential, error) {
	// Look for environment variables in the format: AUTH_USER_<USERNAME>_PASSWORD
	envKey := fmt.Sprintf("AUTH_USER_%s_PASSWORD", strings.ToUpper(username))
	password := os.Getenv(envKey)
	if password == "" {
		return nil, fmt.Errorf("credential not found for user: %s", username)
	}

	// Check for optional salt and iterations for SCRAM-SHA-256
	saltKey := fmt.Sprintf("AUTH_USER_%s_SALT", strings.ToUpper(username))
	iterationsKey := fmt.Sprintf("AUTH_USER_%s_ITERATIONS", strings.ToUpper(username))
	rolesKey := fmt.Sprintf("AUTH_USER_%s_ROLES", strings.ToUpper(username))
	expiresKey := fmt.Sprintf("AUTH_USER_%s_EXPIRES", strings.ToUpper(username))

	cred := &Credential{
		Username: username,
		Password: password,
		Salt:     os.Getenv(saltKey),
		Metadata: make(map[string]string),
	}

	if iterationsStr := os.Getenv(iterationsKey); iterationsStr != "" {
		cred.Iterations = cast.ToInt(iterationsStr)
	}

	if rolesStr := os.Getenv(rolesKey); rolesStr != "" {
		cred.Roles = strings.Split(rolesStr, ",")
	}

	if expiresStr := os.Getenv(expiresKey); expiresStr != "" {
		if expiresAt, err := time.Parse(time.RFC3339, expiresStr); err == nil {
			cred.ExpiresAt = &expiresAt
		}
	}

	return cred, nil
}

func (e *EnvCredentialStore) ValidateCredential(ctx context.Context, username, password string) (*Credential, error) {
	cred, err := e.GetCredential(ctx, username)
	if err != nil {
		return nil, err
	}

	if e.IsExpired(cred) {
		return nil, fmt.Errorf("credential expired for user: %s", username)
	}

	if cred.Password != password {
		return nil, fmt.Errorf("invalid password for user: %s", username)
	}

	return cred, nil
}

func (e *EnvCredentialStore) ValidateCertificate(ctx context.Context, cert *x509.Certificate) (*Credential, error) {
	// For environment backend, we can check if there's a mapping from cert subject to username
	subject := cert.Subject.CommonName
	if subject == "" {
		return nil, fmt.Errorf("certificate has no common name")
	}

	// Check if there's a user mapping for this certificate
	envKey := fmt.Sprintf("AUTH_CERT_%s_USERNAME", strings.ToUpper(subject))
	username := os.Getenv(envKey)
	if username == "" {
		return nil, fmt.Errorf("no user mapping found for certificate subject: %s", subject)
	}

	cred, err := e.GetCredential(ctx, username)
	if err != nil {
		return nil, err
	}

	cred.Certificate = cert
	return cred, nil
}

func (e *EnvCredentialStore) IsExpired(cred *Credential) bool {
	if cred.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*cred.ExpiresAt)
}

// FileCredentialStore implementation
func (f *FileCredentialStore) GetCredential(ctx context.Context, username string) (*Credential, error) {
	credentials, err := f.loadCredentials()
	if err != nil {
		return nil, err
	}

	for _, cred := range credentials {
		if cred.Username == username {
			return &cred, nil
		}
	}

	return nil, fmt.Errorf("credential not found for user: %s", username)
}

func (f *FileCredentialStore) ValidateCredential(ctx context.Context, username, password string) (*Credential, error) {
	cred, err := f.GetCredential(ctx, username)
	if err != nil {
		return nil, err
	}

	if f.IsExpired(cred) {
		return nil, fmt.Errorf("credential expired for user: %s", username)
	}

	if cred.Password != password {
		return nil, fmt.Errorf("invalid password for user: %s", username)
	}

	return cred, nil
}

func (f *FileCredentialStore) ValidateCertificate(ctx context.Context, cert *x509.Certificate) (*Credential, error) {
	// For file backend, we need to find a user with matching certificate info
	subject := cert.Subject.CommonName
	if subject == "" {
		return nil, fmt.Errorf("certificate has no common name")
	}

	credentials, err := f.loadCredentials()
	if err != nil {
		return nil, err
	}

	for _, cred := range credentials {
		if cred.Metadata != nil && cred.Metadata["cert_subject"] == subject {
			cred.Certificate = cert
			return &cred, nil
		}
	}

	return nil, fmt.Errorf("no user mapping found for certificate subject: %s", subject)
}

func (f *FileCredentialStore) IsExpired(cred *Credential) bool {
	if cred.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*cred.ExpiresAt)
}

func (f *FileCredentialStore) loadCredentials() ([]Credential, error) {
	if !filepath.IsAbs(f.filePath) {
		return nil, fmt.Errorf("file path must be absolute: %s", f.filePath)
	}

	data, err := os.ReadFile(f.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var credentials []Credential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return credentials, nil
}

// VaultCredentialStore implementation
func (v *VaultCredentialStore) GetCredential(ctx context.Context, username string) (*Credential, error) {
	path := fmt.Sprintf("%s/data/users/%s", v.mountPath, username)
	url := fmt.Sprintf("%s/v1/%s", v.address, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to vault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("credential not found for user: %s", username)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var vaultResp struct {
		Data struct {
			Data Credential `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return nil, fmt.Errorf("failed to parse vault response: %v", err)
	}

	return &vaultResp.Data.Data, nil
}

func (v *VaultCredentialStore) ValidateCredential(ctx context.Context, username, password string) (*Credential, error) {
	cred, err := v.GetCredential(ctx, username)
	if err != nil {
		return nil, err
	}

	if v.IsExpired(cred) {
		return nil, fmt.Errorf("credential expired for user: %s", username)
	}

	if cred.Password != password {
		return nil, fmt.Errorf("invalid password for user: %s", username)
	}

	return cred, nil
}

func (v *VaultCredentialStore) ValidateCertificate(ctx context.Context, cert *x509.Certificate) (*Credential, error) {
	subject := cert.Subject.CommonName
	if subject == "" {
		return nil, fmt.Errorf("certificate has no common name")
	}

	// Try to find user by certificate subject
	path := fmt.Sprintf("%s/data/certs/%s", v.mountPath, subject)
	url := fmt.Sprintf("%s/v1/%s", v.address, path)

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to vault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no user mapping found for certificate subject: %s", subject)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var vaultResp struct {
		Data struct {
			Data struct {
				Username string `json:"username"`
			} `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return nil, fmt.Errorf("failed to parse vault response: %v", err)
	}

	// Now get the user credential
	cred, err := v.GetCredential(context.Background(), vaultResp.Data.Data.Username)
	if err != nil {
		return nil, err
	}

	cred.Certificate = cert
	return cred, nil
}

func (v *VaultCredentialStore) IsExpired(cred *Credential) bool {
	if cred.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*cred.ExpiresAt)
}
