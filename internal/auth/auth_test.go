package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tcs := []struct {
		name      string
		headers   map[string]string
		want      string
		shouldErr bool
		wantErr   error
	}{
		{
			name: "Valid API Key",
			headers: map[string]string{
				"Authorization": "ApiKey EEYORE",
			},
			want: "EEYORE",
		},
		{
			name:      "No Header",
			headers:   map[string]string{},
			shouldErr: true,
			wantErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header",
			headers: map[string]string{
				"Authorization": "ApiKey",
			},
			shouldErr: true,
		},
		{
			name: "Incorrect Name",
			headers: map[string]string{
				"Authorization": "Bearer ABC",
			},
			shouldErr: true,
		},
	}

	for _, tc := range tcs {
		headers := http.Header{}

		for k, v := range tc.headers {
			headers.Add(k, v)
		}

		apiKey, err := GetAPIKey(headers)

		if !tc.shouldErr {
			if err != nil {
				t.Errorf("%s: unexpected error. want=nil, got='%s'",
					tc.name, err.Error())
			} else if tc.want != apiKey {
				t.Errorf("%s: unexpected API key. want='%s', got='%s'",
					tc.name, tc.want, apiKey)
			}
		} else {
			if err == nil {
				if tc.wantErr != nil {
					t.Errorf("%s: no error. want='%s', got=nil",
						tc.name, tc.wantErr.Error())
				} else {
					t.Errorf("%s: no error. want=not nil, got=nil",
						tc.name)
				}
			} else {
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("%s: wrong error. want='%s', got='%s'",
						tc.name, tc.wantErr.Error(), err)
				}
			}
		}
	}
}
