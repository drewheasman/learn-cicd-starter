package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testTable := []struct {
		name          string
		key           string
		value         string
		expectedToken string
		gotError      error
	}{
		{
			name:          "Valid ApiKey format",
			key:           "Authorization",
			value:         "ApiKey 12345",
			expectedToken: "12345",
			gotError:      nil,
		},
		{
			name:          "Missing ApiKey keyword",
			key:           "Authorization",
			value:         "12345",
			expectedToken: "",
			gotError:      ErrMalformedAuthorizationHeader,
		},
		{
			name:          "Empty header",
			key:           "Authorization",
			value:         "",
			expectedToken: "",
			gotError:      ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Too many parts",
			key:           "Authorization",
			value:         "ApiLey 12345 67890",
			expectedToken: "",
			gotError:      ErrMalformedAuthorizationHeader,
		},
	}

	headers := http.Header{}
	for _, v := range testTable {
		t.Run(v.name, func(t *testing.T) {
			headers.Set(v.key, v.value)
			token, err := GetAPIKey(headers)
			if err != v.gotError {
				t.Fatalf("GetAPIKey() resulted in error: %v", err)
			}

			if token != v.expectedToken {
				t.Fatalf("Expected %v got %v", v.expectedToken, token)
			}
		})
	}
}
