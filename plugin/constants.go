package plugin

type AuthType string

const (
	CLEARTEXTPASSWORD AuthType = "cleartext_password"
	MD5               AuthType = "md5"
	SCRAMSHA256       AuthType = "scram-sha-256"

	SALT_SIZE           = 4
	MD5_PASSWORD_LENGTH = 35
)
