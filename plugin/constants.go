package plugin

type AuthType string

const (
	CLEARTEXT_PASSWORD AuthType = "cleartext_password"
	MD5                AuthType = "md5"
	SCRAM_SHA_256      AuthType = "scram-sha-256"

	STARTUP_MESSAGE     = "startupMessage"
	PASSWORD_MESSAGE    = "passwordMessage"
	USER                = "user"
	PASSWORD            = "Password"
	SALT_SIZE           = 4
	MD5_PASSWORD_LENGTH = 35
)
