package utils

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
)

type APIClient struct {
	Client *resty.Client
}

// convertHeaders converts http.Header to map[string]string
func convertHeaders(headers http.Header) map[string]string {
	converted := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			converted[key] = values[0]
		}
	}
	return converted
}

type APIResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
}

// NewAPIClient creates a new API client with default settings
func NewAPIClient() *APIClient {
	client := resty.New().
		SetTimeout(30*1000000000). // 30 seconds
		SetHeader("Content-Type", "application/json")
	return &APIClient{Client: client}
}

// Post sends a POST request to the specified URL with the given payload
func (api *APIClient) Post(url string, payload interface{}, headers map[string]string) (*APIResponse, error) {
	// Add headers if provided
	req := api.Client.R()
	if headers != nil {
		req.SetHeaders(headers)
	}

	// Set payload as JSON
	resp, err := req.SetBody(payload).Post(url)
	if err != nil {
		return nil, fmt.Errorf("API POST call failed: %w", err)
	}

	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return nil, errors.New(string(resp.Body()))
	}

	return &APIResponse{
		StatusCode: resp.StatusCode(),
		Body:       resp.Body(),
		Headers:    convertHeaders(resp.Header()),
	}, nil
}
