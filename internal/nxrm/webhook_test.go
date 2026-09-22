/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nxrm

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // matching NXRM's own webhook signing algorithm
	"encoding/hex"
	"strings"
	"testing"
)

func sign(t *testing.T, body []byte, secret string) string {
	t.Helper()
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyHMAC(t *testing.T) {
	body := []byte(`{"repositoryName":"maven-releases","action":"CREATED"}`)
	secret := "shared-secret"

	t.Run("valid signature", func(t *testing.T) {
		sig := sign(t, body, secret)
		if !VerifyHMAC(body, sig, secret) {
			t.Fatal("expected valid signature to verify")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		sig := sign(t, body, secret)
		if VerifyHMAC(body, sig, "wrong-secret") {
			t.Fatal("expected verification to fail with wrong secret")
		}
	})

	t.Run("tampered body", func(t *testing.T) {
		sig := sign(t, body, secret)
		tampered := []byte(`{"repositoryName":"maven-releases","action":"DELETED"}`)
		if VerifyHMAC(tampered, sig, secret) {
			t.Fatal("expected verification to fail for tampered body")
		}
	})

	t.Run("garbage signature", func(t *testing.T) {
		if VerifyHMAC(body, "not-a-valid-hex-signature", secret) {
			t.Fatal("expected verification to fail for malformed signature")
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		if VerifyHMAC(body, "", secret) {
			t.Fatal("expected verification to fail for empty signature")
		}
	})
}

func TestParseWebhookPayload(t *testing.T) {
	body := `{
		"repositoryName": "maven-releases",
		"action": "CREATED",
		"component": {
			"componentId": "abc123",
			"format": "maven2",
			"name": "jackson-core",
			"group": "com.fasterxml.jackson.core",
			"version": "2.13.5.1-osera-00001"
		}
	}`

	payload, err := ParseWebhookPayload(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload.RepositoryName != "maven-releases" {
		t.Errorf("RepositoryName = %q, want %q", payload.RepositoryName, "maven-releases")
	}
	if payload.Action != ActionCreated {
		t.Errorf("Action = %q, want %q", payload.Action, ActionCreated)
	}
	if payload.Component.ComponentID != "abc123" {
		t.Errorf("Component.ComponentID = %q, want %q", payload.Component.ComponentID, "abc123")
	}
	if payload.Component.Format != "maven2" {
		t.Errorf("Component.Format = %q, want %q", payload.Component.Format, "maven2")
	}
}

func TestParseWebhookPayload_invalidJSON(t *testing.T) {
	_, err := ParseWebhookPayload(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
