package onfido

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
)

// WebhookEnvironment represents an environment type (see `WebhookEnvironment*` constants for possible values)
type WebhookEnvironment string

// WebhookEvent represents an event type (see `WebhookEvent*` constants for possible values)
type WebhookEvent string

// Constants
const (
	WebhookSignatureHeader = "X-Signature"
	WebhookTokenEnv        = "ONFIDO_WEBHOOK_TOKEN"

	WebhookEnvironmentSandbox WebhookEnvironment = "sandbox"
	WebhookEnvironmentLive    WebhookEnvironment = "live"

	WebhookEventReportWithdrawn        WebhookEvent = "report.withdrawn"
	WebhookEventReportResumed          WebhookEvent = "report.resumed"
	WebhookEventReportCancelled        WebhookEvent = "report.cancelled"
	WebhookEventReportAwaitingApproval WebhookEvent = "report.awaiting_approval"
	WebhookEventReportInitiated        WebhookEvent = "report.initiated"
	WebhookEventReportCompleted        WebhookEvent = "report.completed"
	WebhookEventCheckStarted           WebhookEvent = "check.started"
	WebhookEventCheckReopened          WebhookEvent = "check.reopened"
	WebhookEventCheckWithdrawn         WebhookEvent = "check.withdrawn"
	WebhookEventCheckCompleted         WebhookEvent = "check.completed"
	WebhookEventCheckFormOpened        WebhookEvent = "check.form_opened"
	WebhookEventCheckFormCompleted     WebhookEvent = "check.form_completed"
)

// Webhook errors
var (
	ErrInvalidWebhookSignature = errors.New("invalid request, payload hash doesn't match signature")
	ErrMissingWebhookToken     = errors.New("webhook token not found in environmental variable")
)

// Webhook represents a webhook handler
type Webhook struct {
	Token string
}

// WebhookRefRequest represents a webhook request to Onfido API
type WebhookRefRequest struct {
	URL string `json:"url"` // must be HTTPS
	// Enabled   bool                 `json:"enabled"`                // omitted so it defaults to true
	Environments []WebhookEnvironment `json:"environments,omitempty"` // defaults to both
	Events       []WebhookEvent       `json:"events,omitempty"`       // defaults to all
}

// WebhookRef represents a webhook in Onfido API
type WebhookRef struct {
	ID           string               `json:"id,omitempty"`
	URL          string               `json:"url,omitempty"`
	Enabled      bool                 `json:"enabled"`
	Href         string               `json:"href,omitempty"`
	Token        string               `json:"token,omitempty"`
	Environments []WebhookEnvironment `json:"environments,omitempty"`
	Events       []WebhookEvent       `json:"events,omitempty"`
}

// WebhookRefs represents a list of webhooks in Onfido API
type WebhookRefs struct {
	Webhooks []*WebhookRef `json:"webhooks"`
}

// WebhookRequest represents an incoming webhook request from Onfido
type WebhookRequest struct {
	Payload struct {
		ResourceType string `json:"resource_type"`
		Action       string `json:"action"`
		Object       struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			CompletedAt string `json:"completed_at"`
			Href        string `json:"href"`
		} `json:"object"`
	} `json:"payload"`
}

// NewWebhookFromEnv creates a new webhook handler using
// configuration from environment variables.
func NewWebhookFromEnv() (*Webhook, error) {
	token := os.Getenv(WebhookTokenEnv)
	if token == "" {
		return nil, ErrMissingWebhookToken
	}
	return NewWebhook(token), nil
}

// NewWebhook creates a new webhook handler
func NewWebhook(token string) *Webhook {
	return &Webhook{
		Token: token,
	}
}

// ValidateSignature validates the request body against the signature header.
func (wh *Webhook) ValidateSignature(body []byte, signature string) error {
	mac := hmac.New(sha1.New, []byte(wh.Token))
	if _, err := mac.Write(body); err != nil {
		return err
	}

	sig, err := hex.DecodeString(signature)
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrInvalidWebhookSignature
	}

	return nil
}

// ParseFromRequest parses the webhook request body and returns
// it as WebhookRequest if the request signature is valid.
func (wh *Webhook) ParseFromRequest(req *http.Request) (*WebhookRequest, error) {
	signature := req.Header.Get(WebhookSignatureHeader)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()

	if err := wh.ValidateSignature(body, signature); err != nil {
		return nil, err
	}

	var wr WebhookRequest
	if err := json.Unmarshal(body, &wr); err != nil {
		return nil, err
	}

	return &wr, nil
}

// CreateWebhook register a new webhook.
// see https://documentation.onfido.com/#register-webhook
func (c *Client) CreateWebhook(ctx context.Context, wr WebhookRefRequest) (*WebhookRef, error) {
	jsonStr, err := json.Marshal(wr)
	if err != nil {
		return nil, err
	}

	req, err := c.newRequest("POST", "/webhooks", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}

	var resp WebhookRef
	_, err = c.do(ctx, req, &resp)
	return &resp, err
}

// WebhookRefIter represents a webhook iterator
type WebhookRefIter struct {
	*iter
}

// Webhook returns the current item in the iterator as a WebhookRef.
func (i *WebhookRefIter) Webhook() *WebhookRef {
	return i.Current().(*WebhookRef)
}

// ListWebhooks retrieves the list of webhooks.
// see https://documentation.onfido.com/#list-webhooks
func (c *Client) ListWebhooks() *WebhookRefIter {
	handler := func(body []byte) ([]interface{}, error) {
		var r WebhookRefs
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}

		values := make([]interface{}, len(r.Webhooks))
		for i, v := range r.Webhooks {
			values[i] = v
		}
		return values, nil
	}

	return &WebhookRefIter{&iter{
		c:       c,
		nextURL: "/webhooks/",
		handler: handler,
	}}
}
