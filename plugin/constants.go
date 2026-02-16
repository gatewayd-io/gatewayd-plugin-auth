package plugin

// AuthType represents a PostgreSQL authentication method.
type AuthType string

const (
	AuthCleartext   AuthType = "cleartext"
	AuthMD5         AuthType = "md5"
	AuthScramSHA256 AuthType = "scram-sha-256"
)

// AuthState tracks the state machine for a client connection's authentication.
type AuthState int

const (
	StateInit          AuthState = iota // Waiting for StartupMessage
	StateChallengeSent                  // Auth challenge sent, waiting for password/SASL
	StateScramContinue                  // SCRAM server-first sent, waiting for client-final
	StateAuthenticated                  // Successfully authenticated
	StateFailed                         // Authentication failed
)

// PostgreSQL wire protocol field names (as produced by the SDK's HandleClientMessage).
const (
	FieldStartupMessage      = "startupMessage"
	FieldPasswordMessage     = "passwordMessage"
	FieldSASLInitialResponse = "saslInitialResponse"
	FieldSASLResponse        = "saslResponse"
	FieldQuery               = "query"
	FieldParse               = "parse"
	FieldRequest             = "request"
	FieldResponse            = "response"
)

// PostgreSQL startup message parameter keys.
const (
	ParamUser     = "user"
	ParamDatabase = "database"
)

// PostgreSQL error constants.
const (
	ErrorSeverity     = "ERROR"
	ErrorCodeAuthFail = "28P01"
	ErrorCodeDenied   = "42501"
	ErrorMsgAuthFail  = "authentication failed"
	ErrorMsgDenied    = "permission denied"
)

// Salt size for MD5 authentication.
const SaltSize = 4

// MD5 hashed password length ("md5" + 32 hex chars = 35).
const MD5PasswordLength = 35
