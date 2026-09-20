package anubis_test

import (
	"testing"

	anubis "github.com/gsoultan/anubis-sdk"
)

const testKey = "anb_live_testpfx_0123456789abcdefghij"

// TestAPlatformKeyIsDeclaredNotDetected.
//
// The two credential shapes are identical and only Anubis knows which store
// issued one, so this records what the CALL SITE said. That is the whole point:
// a reviewer can see which credential a service holds without reading a
// deployment variable's name.
func TestAPlatformKeyIsDeclaredNotDetected(t *testing.T) {
	platform, err := anubis.New("https://anubis.example",
		anubis.WithApplication("probe", ""), anubis.WithPlatformKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if !platform.IsPlatformCredential() {
		t.Fatal("WithPlatformKey did not record the declaration")
	}

	// The same key through WithAPIKey still works — it always has, and breaking
	// that would break every service already holding one.
	tenant, err := anubis.New("https://anubis.example",
		anubis.WithApplication("probe", ""), anubis.WithAPIKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if tenant.IsPlatformCredential() {
		t.Fatal("WithAPIKey claimed a platform credential; it cannot know")
	}
}

func TestWithPlatformKeyRefusesAMalformedKey(t *testing.T) {
	for _, key := range []string{"", "secret", "Bearer anb_live_x", "anb_test_x"} {
		if _, err := anubis.New("https://anubis.example",
			anubis.WithApplication("probe", ""), anubis.WithPlatformKey(key)); err == nil {
			t.Fatalf("%q was accepted as a platform key", key)
		}
	}
}
