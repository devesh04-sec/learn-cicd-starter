package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Success - Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key-123"},
			},
			expectedKey:   "my-secret-api-key-123",
			expectedError: nil,
		},
		{
			name:          "Failure - Missing Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Failure - Malformed header (missing key)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Failure - Wrong auth type (Bearer instead of ApiKey)",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Failure - Empty string Authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if the returned key matches expected
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() gotKey = %v, want %v", key, tt.expectedKey)
			}

			// Check error handling
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("GetAPIKey() expected error '%v', but got nil", tt.expectedError)
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.expectedError)
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error: %v", err)
			}
		})
	}
}
