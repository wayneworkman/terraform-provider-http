# HTTP Provider: Environment-Variable Authentication

Terraform’s `http` data source now supports four authentication methods via environment variables, *without* adding any new configuration attributes.

## Env-Var Naming

All auth parameters follow:

```
TF_HTTP_<AUTH_PARAM>_<NORMALIZED_ADDRESS>
```

- `<AUTH_PARAM>` is one of:
  - `USR`, `PW` (Basic)
  - `TOKEN_HEADER`, `TOKEN_VALUE` (Token)
  - `OAUTH2_CLIENT_ID`, `OAUTH2_CLIENT_SECRET`, `OAUTH2_TOKEN_URL`, `OAUTH2_SCOPE`, `OAUTH2_AUDIENCE` (OAuth2)
  - `JWT_TOKEN`, `JWT_KEY`, `JWT_ALG` (JWT)
- `<NORMALIZED_ADDRESS>` is the Terraform address:
  1. Strip leading `data.http.`  
  2. Replace every non‐alphanumeric with `_`  
  3. Uppercase

### Examples

```
# Basic Auth for data.http.latest
export TF_HTTP_USR_LATEST=alice
export TF_HTTP_PW_LATEST=secret

# Token Auth for module.nested.http_fetch
export TF_HTTP_TOKEN_HEADER_MODULE_NESTED_HTTP_FETCH=Authorization
export TF_HTTP_TOKEN_VALUE_MODULE_NESTED_HTTP_FETCH="bearer abc123"

# OAuth2 (client_credentials)
export TF_HTTP_OAUTH2_CLIENT_ID_CFG=abc
export TF_HTTP_OAUTH2_CLIENT_SECRET_CFG=shhh
export TF_HTTP_OAUTH2_TOKEN_URL_CFG=https://auth.example.com/token
export TF_HTTP_OAUTH2_SCOPE_CFG="read write"
export TF_HTTP_OAUTH2_AUDIENCE_CFG=some-api

# Pre-generated JWT
export TF_HTTP_JWT_TOKEN_MYDATA=eyJhbGciOiJSUzI1...
```

## Precedence

1. **JWT** (pre-generated or self-signed)  
2. **OAuth2** (client credentials)  
3. **Token-based**  
4. **Basic**

If multiple schemes are detected for the same address, only the highest‐precedence one is applied; others are ignored.

---

> **Security:** No secrets are stored in state, plan, or logs. Secrets are never emitted by the provider.  
