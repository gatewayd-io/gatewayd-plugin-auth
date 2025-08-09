package plugin

type AuthType string

const (
	CLEARTEXT_PASSWORD AuthType = "cleartext_password"
	MD5                AuthType = "md5"
	SCRAM_SHA_256      AuthType = "scram-sha-256"
	CERT               AuthType = "cert"

	STARTUP_MESSAGE       = "startupMessage"
	PASSWORD_MESSAGE      = "passwordMessage"
	SASL_INITIAL_RESPONSE = "saslInitialResponse"
	SASL_RESPONSE         = "saslResponse"
	USER                  = "user"
	PASSWORD              = "Password"
	SALT_SIZE             = 4
	MD5_PASSWORD_LENGTH   = 35

    ERROR_MESSAGE  = "authentication failed"
	ERROR_SEVERITY = "ERROR"
	ERROR_NUMBER   = "28P01"
)

// Credential backend types
type CredentialBackend string

const (
	ENV_BACKEND   CredentialBackend = "env"
	FILE_BACKEND  CredentialBackend = "file"
	VAULT_BACKEND CredentialBackend = "vault"
)

// SCRAM-SHA-256 constants
const (
	SCRAM_SHA_256_ITERATION_COUNT = 10000
	SCRAM_SHA_256_KEY_LENGTH      = 32
	SCRAM_SHA_256_SALT_LENGTH     = 16
)

// Certificate authentication constants
const (
	CERT_SUBJECT_CN = "CN"
	CERT_ISSUER_CN  = "CN"
)
