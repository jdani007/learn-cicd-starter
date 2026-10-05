package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorizatio", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key != "my-secret-key" {
		t.Errorf("expected key %q, got %q", "my-secret-key", key)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader_WrongPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorizatio", "Bearer my-secret-key")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestGetAPIKey_MalformedHeader_MissingKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorizatio", "ApiKey")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got none")
	}
}
