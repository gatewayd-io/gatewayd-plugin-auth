<p align="center">
  <h3 align="center">gatewayd-plugin-auth</h3>
  <p align="center">GatewayD plugin for authentication, authorization, and access control.</p>
</p>

<p align="center">
    <a href="https://github.com/gatewayd-io/gatewayd-plugin-auth/releases">Download</a> ·
    <a href="https://docs.gatewayd.io/plugins/gatewayd-plugin-auth">Documentation</a>
</p>

## Features

- PostgreSQL wire-protocol authentication (identity brokering between clients and the database)
  - **Cleartext password**
  - **MD5**
  - **SCRAM-SHA-256**
- YAML-based credential store with per-user settings:
  - Allowed auth methods
  - Allowed databases
  - Role assignments
  - Enable/disable users
- Optional [Casbin](https://casbin.org)-based RBAC query authorization:
  - Table-level access control per user/role
  - SQL operation mapping: `SELECT` -> read, `INSERT/UPDATE/DELETE` -> write, `CREATE/DROP/ALTER/TRUNCATE/GRANT/REVOKE` -> admin
- Per-connection session management with TTL-based cleanup
- Prometheus metrics for auth successes, failures, and authorization denials
- Prometheus metrics for counting total RPC method calls
- Logging
- Configurable via environment variables

## Build for testing

To build the plugin for development and testing, run the following command:

```bash
make build-dev
```

Running the above command causes the `go mod tidy` and `go build` to run for compiling and generating the plugin binary in the current directory, named `gatewayd-plugin-auth`.

## Build for production

To build the plugin for production, run the following command:

```bash
make build
```

Running the above command causes the `go mod tidy` and `go build -ldflags "-s -w"` to run for compiling and generating a stripped plugin binary.

## Configuration

### Credentials file

Create a `credentials.yaml` file (see `credentials.example.yaml`):

```yaml
users:
  - username: alice
    password: "s3cret_alice"
    auth_methods: ["scram-sha-256", "md5", "cleartext"]
    roles: ["admin"]
    databases: ["mydb", "analytics"]
    enabled: true

  - username: bob
    password: "b0b_password"
    auth_methods: ["md5"]
    roles: ["readonly"]
    databases: ["mydb"]
    enabled: true
```

### Plugin configuration

Add the plugin to your `gatewayd_plugin.yaml`:

```yaml
plugins:
  - name: gatewayd-plugin-auth
    enabled: True
    localPath: ./gatewayd-plugin-auth
    args: ["--log-level", "info"]
    checksum: <sha256sum of the binary>
    env:
      - MAGIC_COOKIE_KEY=GATEWAYD_PLUGIN
      - MAGIC_COOKIE_VALUE=5712b87aa5d7e9f9e9ab643e6603181c5b796015cb1c09d6f5ada882bf2a1872
      - AUTH_TYPE=md5
      - CREDENTIALS_FILE=./credentials.yaml
      - SERVER_VERSION=17.4
      # Optional: enable query authorization
      # - AUTHORIZATION_ENABLED=true
      # - CASBIN_MODEL_PATH=./model.conf
      # - CASBIN_POLICY_PATH=./policy.csv
```

### Environment variables

| Variable                | Description                                                         | Default            |
| ----------------------- | ------------------------------------------------------------------- | ------------------ |
| `AUTH_TYPE`             | Default authentication method (`cleartext`, `md5`, `scram-sha-256`) | `md5`              |
| `CREDENTIALS_FILE`      | Path to the credentials YAML file                                   | `credentials.yaml` |
| `SERVER_VERSION`        | PostgreSQL version advertised to clients                            | `17.4`             |
| `AUTHORIZATION_ENABLED` | Enable Casbin query authorization                                   | `false`            |
| `CASBIN_MODEL_PATH`     | Path to the Casbin model file                                       |                    |
| `CASBIN_POLICY_PATH`    | Path to the Casbin policy file                                      |                    |

### GatewayD configuration

The backend pool connections must be pre-authenticated. In your `gatewayd.yaml`, add `startupParams` to each client block:

```yaml
clients:
  default:
    writes:
      address: localhost:5432
      startupParams:
        user: postgres
        database: postgres
        password: postgres
```

## Authorization

Query authorization is optional and uses [Casbin](https://casbin.org) with an RBAC model. When enabled, every SQL query from an authenticated session is checked against the policy before being forwarded. See `model.conf` and `policy.example.csv` for the default model and an example policy.

## Sentry

This plugin uses [Sentry](https://sentry.io) for error tracking. Sentry can be configured using the `SENTRY_DSN` environment variable. If `SENTRY_DSN` is not set, Sentry will not be used.
