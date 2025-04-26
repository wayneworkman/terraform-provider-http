// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type authMethod int

const (
	authNone authMethod = iota
	authJWT
	authOAuth2
	authToken
	authBasic
)

// normalizeAddress applies the spec’s rules to a full Terraform address.
func normalizeAddress(address string) string {
	// 1. Strip "data.http." prefix
	a := strings.TrimPrefix(address, "data.http.")
	// 2. Replace non-alphanumeric with '_'
	var buf strings.Builder
	for _, r := range a {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			buf.WriteRune(r)
		} else {
			buf.WriteRune('_')
		}
	}
	// 3. Uppercase
	return strings.ToUpper(buf.String())
}

// injectAuth inspects all TF_HTTP_* env vars in precedence order and sets the Authorization (or other) header.
func injectAuth(req *http.Request, fullAddress string) error {
	suffix := normalizeAddress(fullAddress)

	// 1. JWT (pre-generated)
	if tok := os.Getenv("TF_HTTP_JWT_TOKEN_" + suffix); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}

	// 2. OAuth2 Client Credentials
	clientID := os.Getenv("TF_HTTP_OAUTH2_CLIENT_ID_" + suffix)
	clientSecret := os.Getenv("TF_HTTP_OAUTH2_CLIENT_SECRET_" + suffix)
	tokenURL := os.Getenv("TF_HTTP_OAUTH2_TOKEN_URL_" + suffix)
	if clientID != "" && clientSecret != "" && tokenURL != "" {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
		if scope := os.Getenv("TF_HTTP_OAUTH2_SCOPE_" + suffix); scope != "" {
			form.Set("scope", scope)
		}
		if aud := os.Getenv("TF_HTTP_OAUTH2_AUDIENCE_" + suffix); aud != "" {
			form.Set("audience", aud)
		}

		resp, err := http.PostForm(tokenURL, form)
		if err != nil {
			return fmt.Errorf("oauth2 token request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("oauth2 token endpoint returned %d: %s", resp.StatusCode, string(body))
		}

		var tr struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			return fmt.Errorf("failed decoding oauth2 token response: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
		return nil
	}

	// 3. Token-based
	tokenHeader := os.Getenv("TF_HTTP_TOKEN_HEADER_" + suffix)
	tokenValue := os.Getenv("TF_HTTP_TOKEN_VALUE_" + suffix)
	if tokenHeader != "" && tokenValue != "" {
		req.Header.Set(tokenHeader, tokenValue)
		return nil
	}

	// 4. Basic
	user := os.Getenv("TF_HTTP_USR_" + suffix)
	pass := os.Getenv("TF_HTTP_PW_" + suffix)
	if user != "" && pass != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+creds)
		return nil
	}

	// no auth vars present → no-op
	return nil
}
