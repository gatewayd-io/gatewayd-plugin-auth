package plugin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	"github.com/spf13/cast"
)

var (
	// ErrNoParameters is returned when a startup message has no parameters.
	ErrNoParameters = errors.New("no parameters in startup message")
	// ErrNoUser is returned when a startup message has no user parameter.
	ErrNoUser = errors.New("no user in startup message")
)

// GenerateSalt generates a random salt of SaltSize bytes.
func GenerateSalt(_ int) ([SaltSize]byte, error) {
	var salt [SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return salt, fmt.Errorf("generating salt: %w", err)
	}
	return salt, nil
}

// BuildAuthFailResponse builds a Terminate+ErrorResponse for authentication failure.
func BuildAuthFailResponse(detail string) ([]byte, error) {
	return postgres.BuildTerminateWithError(
		ErrorMsgAuthFail,
		ErrorSeverity,
		ErrorCodeAuthFail,
		detail,
	)
}

// BuildAccessDeniedResponse builds a Terminate+ErrorResponse for authorization denial.
func BuildAccessDeniedResponse(detail string) ([]byte, error) {
	return postgres.BuildTerminateWithError(
		ErrorMsgDenied,
		ErrorSeverity,
		ErrorCodeDenied,
		detail,
	)
}

// DecodeBase64Field decodes a base64-encoded string field from the request struct.
func DecodeBase64Field(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// ParseStartupParams extracts user and database from a decoded startup message.
func ParseStartupParams(startupDecoded []byte) (string, string, error) {
	startupMap := cast.ToStringMap(string(startupDecoded))
	parameters := cast.ToStringMapString(startupMap["Parameters"])
	if parameters == nil {
		return "", "", ErrNoParameters
	}

	user := parameters[ParamUser]
	database := parameters[ParamDatabase]
	if user == "" {
		return "", "", ErrNoUser
	}

	return user, database, nil
}

// ParsePasswordMessage extracts the password from a decoded password message.
func ParsePasswordMessage(passwordDecoded []byte) map[string]string {
	return cast.ToStringMapString(string(passwordDecoded))
}

// GetClientRemote extracts the client remote address from the request fields.
func GetClientRemote(fields map[string]interface{}) string {
	if client, ok := fields["client"]; ok {
		clientMap := cast.ToStringMap(client)
		return cast.ToString(clientMap["remote"])
	}
	return ""
}
