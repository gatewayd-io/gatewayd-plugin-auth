package plugin

import (
    "context"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "strings"

    sdkPlugin "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
    v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
    "github.com/hashicorp/go-hclog"
    "github.com/spf13/cast"
)

// CertificateAuthenticator handles certificate-based authentication
type CertificateAuthenticator struct {
	logger          hclog.Logger
	credentialStore CredentialStore
	caPool          *x509.CertPool
	requireValidCA  bool
}

// NewCertificateAuthenticator creates a new certificate authenticator
func NewCertificateAuthenticator(logger hclog.Logger, credentialStore CredentialStore, caPool *x509.CertPool, requireValidCA bool) *CertificateAuthenticator {
	return &CertificateAuthenticator{
		logger:          logger,
		credentialStore: credentialStore,
		caPool:          caPool,
		requireValidCA:  requireValidCA,
	}
}

// AuthenticateWithCertificate performs certificate-based authentication
func (c *CertificateAuthenticator) AuthenticateWithCertificate(ctx context.Context, req *v1.Struct) (*Credential, error) {
	// Extract TLS connection information
	tlsConn, err := c.extractTLSConnection(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TLS connection: %v", err)
	}

	// Get client certificate
	clientCert, err := c.extractClientCertificate(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client certificate: %v", err)
	}

	// Verify certificate chain
	if err := c.verifyCertificateChain(clientCert); err != nil {
		return nil, fmt.Errorf("certificate verification failed: %v", err)
	}

	// Validate certificate with credential store
	credential, err := c.credentialStore.ValidateCertificate(ctx, clientCert)
	if err != nil {
		return nil, fmt.Errorf("certificate validation failed: %v", err)
	}

	// Check if credential is expired
	if c.credentialStore.IsExpired(credential) {
		return nil, fmt.Errorf("certificate credential has expired")
	}

	c.logger.Info("Certificate authentication successful",
		"username", credential.Username,
		"subject", clientCert.Subject.CommonName,
		"issuer", clientCert.Issuer.CommonName,
		"serial", clientCert.SerialNumber.String())

	return credential, nil
}

// extractTLSConnection extracts TLS connection information from the request
func (c *CertificateAuthenticator) extractTLSConnection(req *v1.Struct) (*tls.ConnectionState, error) {
    client := cast.ToStringMap(sdkPlugin.GetAttr(req, "client", ""))
    if client == nil {
        return nil, fmt.Errorf("no client information found")
    }

    // Check if TLS is enabled
    tlsEnabled := cast.ToBool(client["tls_enabled"])
    if !tlsEnabled {
        return nil, fmt.Errorf("TLS is not enabled")
    }

    // Attempt to parse client certificate from attributes if present
    // Expect PEM in client["tls_client_cert_pem"]
    if pemStr, ok := client["tls_client_cert_pem"]; ok {
        pemBytes := []byte(cast.ToString(pemStr))
        cert, err := parseSingleCertFromPEM(pemBytes)
        if err == nil {
            // Populate minimal tls state with provided cert
            return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, nil
        }
    }

    // Fallback: no access to actual TLS state
    return &tls.ConnectionState{}, nil
}

// extractClientCertificate extracts the client certificate from TLS connection
func (c *CertificateAuthenticator) extractClientCertificate(tlsConn *tls.ConnectionState) (*x509.Certificate, error) {
	if len(tlsConn.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	return tlsConn.PeerCertificates[0], nil
}

// verifyCertificateChain verifies the certificate chain
func (c *CertificateAuthenticator) verifyCertificateChain(cert *x509.Certificate) error {
	if !c.requireValidCA {
		// If CA validation is not required, just check basic certificate validity
		return c.verifyBasicCertificate(cert)
	}

	// Verify against CA pool
	if c.caPool == nil {
		return fmt.Errorf("CA pool not configured but CA validation is required")
	}

	opts := x509.VerifyOptions{
		Roots: c.caPool,
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %v", err)
	}

	return nil
}

// verifyBasicCertificate performs basic certificate validation
func (c *CertificateAuthenticator) verifyBasicCertificate(cert *x509.Certificate) error {
	// Check if certificate has required key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate does not have digital signature key usage")
	}

	return nil
}

// ExtractUsernameFromCertificate extracts username from certificate
func ExtractUsernameFromCertificate(cert *x509.Certificate, mappingRules map[string]string) (string, error) {
	// Try different methods to extract username

	// Method 1: Use common name directly
	if cert.Subject.CommonName != "" {
		if username, exists := mappingRules["cn:"+cert.Subject.CommonName]; exists {
			return username, nil
		}
		// If no mapping rule, use CN directly
		if len(mappingRules) == 0 {
			return cert.Subject.CommonName, nil
		}
	}

	// Method 2: Use email from subject alternative names
	for _, email := range cert.EmailAddresses {
		if username, exists := mappingRules["email:"+email]; exists {
			return username, nil
		}
		// Extract username from email (part before @)
		if len(mappingRules) == 0 {
			parts := strings.Split(email, "@")
			if len(parts) > 0 {
				return parts[0], nil
			}
		}
	}

	// Method 3: Use organization unit
	if len(cert.Subject.OrganizationalUnit) > 0 {
		ou := cert.Subject.OrganizationalUnit[0]
		if username, exists := mappingRules["ou:"+ou]; exists {
			return username, nil
		}
	}

	return "", fmt.Errorf("unable to extract username from certificate")
}

// LoadCAPool loads CA certificates from various sources
func LoadCAPool(config map[string]interface{}) (*x509.CertPool, error) {
	caPool := x509.NewCertPool()

	// Load from system CA pool
	if cast.ToBool(config["use_system_ca"]) {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %v", err)
		}
		caPool = systemPool
	}

	// Load from PEM data
	if caData := cast.ToString(config["ca_data"]); caData != "" {
		if !caPool.AppendCertsFromPEM([]byte(caData)) {
			return nil, fmt.Errorf("failed to parse CA certificates from PEM data")
		}
	}

	return caPool, nil
}

// GetCertificateFingerprint returns the SHA256 fingerprint of the certificate
func GetCertificateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

// GetCertificateInfo returns detailed information about the certificate
func GetCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	return map[string]interface{}{
		"subject":         cert.Subject.String(),
		"issuer":          cert.Issuer.String(),
		"serial_number":   cert.SerialNumber.String(),
		"not_before":      cert.NotBefore,
		"not_after":       cert.NotAfter,
		"is_ca":           cert.IsCA,
		"key_usage":       cert.KeyUsage,
		"ext_key_usage":   cert.ExtKeyUsage,
		"email_addresses": cert.EmailAddresses,
		"dns_names":       cert.DNSNames,
		"ip_addresses":    cert.IPAddresses,
		"fingerprint":     GetCertificateFingerprint(cert),
	}
}

// parseSingleCertFromPEM parses first certificate from PEM
func parseSingleCertFromPEM(pemBytes []byte) (*x509.Certificate, error) {
    var block *pem.Block
    for {
        block, pemBytes = pem.Decode(pemBytes)
        if block == nil {
            break
        }
        if block.Type == "CERTIFICATE" {
            return x509.ParseCertificate(block.Bytes)
        }
    }
    return nil, fmt.Errorf("no certificate found in PEM")
}
