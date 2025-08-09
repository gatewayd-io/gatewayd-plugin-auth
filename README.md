# GatewayD Authentication Plugin

A comprehensive authentication plugin for GatewayD that provides centralized authentication, multiple credential backends, and support for various PostgreSQL authentication methods.

## Features

### Supported Authentication Methods

- **Cleartext Password** (`cleartext_password`) - Simple plaintext password authentication
- **MD5** (`md5`) - PostgreSQL MD5 password authentication with salt
- **SCRAM-SHA-256** (`scram-sha-256`) - Secure challenge-response authentication (requires TLS)
- **Certificate** (`cert`) - X.509 certificate-based authentication (requires TLS)

### Credential Backends

- **Environment Variables** (`env`) - Store credentials in environment variables
- **JSON File** (`file`) - Store credentials in a JSON file
- **HashiCorp Vault** (`vault`) - Store credentials in Vault KV store

### Security Features

- Credential expiration support
- Role-based access control (RBAC) ready
- TLS requirement for secure authentication methods
- Certificate validation and CA verification
- Audit logging for authentication events

## Configuration

### Basic Configuration

Set the authentication type and credential backend:

```yaml
env:
  - AUTH_TYPE=scram-sha-256
  - CREDENTIAL_BACKEND=env
```

### Environment Variables Backend

When using `CREDENTIAL_BACKEND=env`, define user credentials as environment variables:

```yaml
env:
  - AUTH_USER_POSTGRES_PASSWORD=postgres
  - AUTH_USER_POSTGRES_SALT=randomsalt
  - AUTH_USER_POSTGRES_ITERATIONS=10000
  - AUTH_USER_POSTGRES_ROLES=superuser
  - AUTH_USER_ADMIN_PASSWORD=admin123
  - AUTH_USER_ADMIN_EXPIRES=2025-12-31T23:59:59Z
```

### File Backend

When using `CREDENTIAL_BACKEND=file`, specify the path to your credentials file:

```yaml
env:
  - CREDENTIAL_BACKEND=file
  - CREDENTIAL_FILE_PATH=/etc/gatewayd/credentials.json
```

Example `credentials.json`:
```json
[
  {
    "username": "admin",
    "password": "admin123",
    "salt": "randomsalt",
    "iterations": 10000,
    "expires_at": "2025-12-31T23:59:59Z",
    "roles": ["admin", "read", "write"],
    "metadata": {
      "department": "engineering"
    }
  }
]
```

### Vault Backend

When using `CREDENTIAL_BACKEND=vault`, configure Vault connection:

```yaml
env:
  - CREDENTIAL_BACKEND=vault
  - VAULT_ADDRESS=https://vault.example.com:8200
  - VAULT_TOKEN=your-vault-token
  - VAULT_MOUNT_PATH=secret
```

Store credentials in Vault at `secret/data/users/<username>`:
```json
{
  "data": {
    "username": "admin",
    "password": "admin123",
    "salt": "randomsalt",
    "iterations": 10000,
    "roles": ["admin"]
  }
}
```

### Certificate Authentication

Enable certificate-based authentication:

```yaml
env:
  - AUTH_TYPE=cert
  - CERT_AUTH_ENABLED=true
  - CERT_REQUIRE_VALID_CA=true
  - CERT_USE_SYSTEM_CA=false
  - CERT_CA_DATA=|
    -----BEGIN CERTIFICATE-----
    ... your CA certificate ...
    -----END CERTIFICATE-----
```

Map certificate subjects to usernames:
```yaml
env:
  - AUTH_CERT_ADMIN@EXAMPLE.COM_USERNAME=admin
  - AUTH_CERT_USER@EXAMPLE.COM_USERNAME=readonly
```

## Authentication Methods

### SCRAM-SHA-256

SCRAM-SHA-256 provides secure authentication using salted challenge-response. It requires:
- TLS connection
- Pre-computed salt and iteration count
- Client and server nonce exchange

Example client connection:
```bash
psql "postgresql://username@localhost:5432/database?sslmode=require"
```

### Certificate Authentication

Certificate authentication uses X.509 client certificates. It requires:
- TLS connection with client certificate
- Valid certificate chain (optional)
- Certificate-to-username mapping

Example client connection with certificate:
```bash
psql "postgresql://localhost:5432/database?sslmode=require&sslcert=client.crt&sslkey=client.key&sslrootcert=ca.crt"
```

### MD5 Authentication

MD5 authentication uses PostgreSQL's legacy MD5 method:
- Combines password + username + salt
- Double MD5 hashing
- Less secure than SCRAM-SHA-256

### Cleartext Password

Simple plaintext password authentication:
- Passwords sent in clear text
- Should only be used over TLS
- Not recommended for production

## Environment Variables Reference

### Core Configuration
- `AUTH_TYPE`: Authentication method (cleartext_password, md5, scram-sha-256, cert)
- `CREDENTIAL_BACKEND`: Credential storage backend (env, file, vault)
- `API_GRPC_ADDRESS`: GatewayD API gRPC address

### Environment Backend
- `AUTH_USER_<USERNAME>_PASSWORD`: User password
- `AUTH_USER_<USERNAME>_SALT`: User salt (for SCRAM)
- `AUTH_USER_<USERNAME>_ITERATIONS`: PBKDF2 iterations (for SCRAM)
- `AUTH_USER_<USERNAME>_ROLES`: Comma-separated roles
- `AUTH_USER_<USERNAME>_EXPIRES`: Expiration time (RFC3339 format)

### File Backend
- `CREDENTIAL_FILE_PATH`: Path to credentials JSON file

### Vault Backend
- `VAULT_ADDRESS`: Vault server address
- `VAULT_TOKEN`: Vault authentication token
- `VAULT_MOUNT_PATH`: Vault mount path (default: secret)
- `VAULT_INSECURE_SKIP_VERIFY`: Skip TLS verification (default: false)

### Certificate Authentication
- `CERT_AUTH_ENABLED`: Enable certificate authentication
- `CERT_REQUIRE_VALID_CA`: Require valid CA signature
- `CERT_USE_SYSTEM_CA`: Use system CA pool
- `CERT_CA_DATA`: PEM-encoded CA certificates
- `AUTH_CERT_<SUBJECT>_USERNAME`: Map certificate subject to username

## Security Considerations

1. **Use TLS**: Enable TLS for all authentication methods except legacy MD5
2. **Credential Rotation**: Regularly rotate passwords and certificates
3. **Expiration**: Set appropriate expiration times for credentials
4. **CA Validation**: Use proper CA validation for certificate authentication
5. **Audit Logging**: Monitor authentication events in GatewayD logs

## Building

```bash
make build
```

## Testing

```bash
make test
```

## License

Apache 2.0
