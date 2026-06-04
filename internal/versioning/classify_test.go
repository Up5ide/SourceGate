package versioning

import "testing"

func TestNPMPrerelease(t *testing.T) {
	cases := map[string]bool{
		"1.2.3":                  false,
		"1.2.3-beta.1":           true,
		"0.0.0-experimental-abc": true,
	}
	for value, want := range cases {
		got, err := NPMPrerelease(value)
		if err != nil {
			t.Fatalf("NPMPrerelease(%q) returned error: %v", value, err)
		}
		if got != want {
			t.Fatalf("NPMPrerelease(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestPyPIPreRelease(t *testing.T) {
	cases := map[string]bool{
		"2.0.50":   false,
		"2.1.0b2":  true,
		"3.0rc1":   true,
		"1!2.0.0":  false,
		"1.0.dev1": true,
	}
	for value, want := range cases {
		got, err := PyPIPreRelease(value)
		if err != nil {
			t.Fatalf("PyPIPreRelease(%q) returned error: %v", value, err)
		}
		if got != want {
			t.Fatalf("PyPIPreRelease(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestVersionClassifiersRejectMalformedVersions(t *testing.T) {
	if _, err := NPMPrerelease("latest"); err == nil {
		t.Fatalf("NPMPrerelease returned nil error")
	}
	if _, err := PyPIPreRelease("not a version"); err == nil {
		t.Fatalf("PyPIPreRelease returned nil error")
	}
}
