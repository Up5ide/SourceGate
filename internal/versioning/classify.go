package versioning

import (
	"fmt"
	"regexp"
	"strings"
)

var npmVersionPattern = regexp.MustCompile(`^(?:v)?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// This follows the public PEP 440 normalization grammar closely enough to
// classify registry versions without invoking Python during metadata fetches.
var pypiVersionPattern = regexp.MustCompile(`(?i)^[ \t]*v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:-(?:[0-9]+)|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?[ \t]*$`)
var pypiPrereleasePattern = regexp.MustCompile(`(?i)(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*|[-_.]?dev[-_.]?[0-9]*)`)

func NPMPrerelease(value string) (bool, error) {
	matches := npmVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if matches == nil {
		return false, fmt.Errorf("invalid npm semantic version %q", value)
	}
	return matches[1] != "", nil
}

func ValidNPMVersion(value string) bool {
	return npmVersionPattern.MatchString(strings.TrimSpace(value))
}

func PyPIPreRelease(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if !pypiVersionPattern.MatchString(value) {
		return false, fmt.Errorf("invalid PEP 440 version %q", value)
	}
	return pypiPrereleasePattern.MatchString(value), nil
}

func ValidPyPIVersion(value string) bool {
	return pypiVersionPattern.MatchString(strings.TrimSpace(value))
}
