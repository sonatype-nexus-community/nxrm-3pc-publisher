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
	"crypto/sha1" //nolint:gosec // required: NXRM signs webhook payloads with HMAC-SHA1, not a choice this tool controls.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// WebhookEventID header values this tool acts on. Anything else is ignored.
const ComponentWebhookEventID = "rm:repository:component"

// WebhookPayload is the JSON body of an NXRM `rm:repository:component`
// webhook delivery, restricted to the fields this tool needs. NXRM sends
// additional fields (timestamp, nodeId, initiator, ...) which are ignored.
type WebhookPayload struct {
	RepositoryName string             `json:"repositoryName"`
	Action         string             `json:"action"`
	Component      WebhookComponentXO `json:"component"`
}

// WebhookComponentXO is the `component` object within a component webhook
// payload. Per NXRM's webhook documentation, `componentId` is the id to use
// against the REST API (as opposed to `id`, which is for Groovy scripting).
type WebhookComponentXO struct {
	ComponentID string `json:"componentId"`
	Format      string `json:"format"`
	Name        string `json:"name"`
	Group       string `json:"group"`
	Version     string `json:"version"`
}

// ActionUpdated is the WebhookPayload.Action value for a component whose
// data changed. NXRM sends one each time an asset is attached to a component,
// which makes it a useful "something arrived" signal while a multi-file
// upload is still in progress.
const ActionUpdated = "UPDATED"

// ActionCreated is the WebhookPayload.Action value for a newly
// created/uploaded component.
const ActionCreated = "CREATED"

// VerifyHMAC reports whether signatureHeader (the value of NXRM's
// X-Nexus-Webhook-Signature request header) is a valid HMAC-SHA1 signature
// of body under secret. NXRM computes the signature over the raw request
// body, so callers must pass the exact bytes received, before any JSON
// re-serialization.
func VerifyHMAC(body []byte, signatureHeader, secret string) bool {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signatureHeader))
}

// ParseWebhookPayload decodes an NXRM component webhook request body.
func ParseWebhookPayload(body io.Reader) (WebhookPayload, error) {
	var p WebhookPayload
	if err := json.NewDecoder(body).Decode(&p); err != nil {
		return WebhookPayload{}, fmt.Errorf("decoding webhook payload: %w", err)
	}
	return p, nil
}
