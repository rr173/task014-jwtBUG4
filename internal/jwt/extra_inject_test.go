package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

// TestExtraCannotInjectStandardClaims verifies that Extra map entries using
// standard claim keys (iss, sub, aud, jti, exp, nbf, iat) are cleaned out
// during MarshalJSON, preventing injection of fake standard claims.
func TestExtraCannotInjectStandardClaims(t *testing.T) {
	secret := []byte("secret")
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	v := Verifier{Secret: secret, Now: func() time.Time { return now }}

	// Claims with empty Audience but Extra["aud"] set to injected value.
	// MarshalJSON should NOT allow Extra to inject "aud" into the token payload.
	claims := Claims{
		Subject: "alice",
		Extra:   map[string]any{"aud": "injected-audience", "iss": "injected-issuer"},
	}
	token, err := Sign(claims, secret)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	// "aud" and "iss" should not appear in the verified claims because
	// Audience and Issuer were empty - Extra should not be able to inject them.
	if c.Audience == "injected-audience" {
		t.Fatalf("Extra[\"aud\"] was injected into Audience via MarshalJSON; this is a security issue")
	}
	if c.Issuer == "injected-issuer" {
		t.Fatalf("Extra[\"iss\"] was injected into Issuer via MarshalJSON; this is a security issue")
	}
}

// TestExtraStandardKeysStrippedFromPayload verifies the token payload JSON
// does not contain standard claim keys sourced from Extra.
func TestExtraStandardKeysStrippedFromPayload(t *testing.T) {
	claims := Claims{
		Subject: "alice",
		Extra:   map[string]any{"sub": "evil", "exp": 9999999999},
	}
	b, err := claims.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)

	// "sub" should be "alice" (from Subject field), not "evil" (from Extra)
	if m["sub"] != "alice" {
		t.Fatalf("Subject field should always win over Extra[\"sub\"], got %v", m["sub"])
	}
	// "exp" from Extra should be stripped because ExpiresAt is nil (not set)
	// Standard time claim keys in Extra should be removed to prevent injection.
	if _, ok := m["exp"]; ok {
		t.Fatalf("Extra[\"exp\"] should be stripped when ExpiresAt is nil, but found %v", m["exp"])
	}
}
