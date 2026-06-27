package artifact

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/version"
)

const MaxDownloadSize int64 = 100 * 1024 * 1024

func DownloadAndVerify(ctx context.Context, client *http.Client, candidate report.ArtifactCandidate, use func(string) error) (report.ArtifactDownloadSummary, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if err := validateCandidate(candidate); err != nil {
		return report.ArtifactDownloadSummary{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.URL, nil)
	if err != nil {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("create artifact download request: %w", err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("download artifact %s: %w", candidate.Filename, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("download artifact %s: server returned status %d", candidate.Filename, resp.StatusCode)
	}
	if resp.ContentLength > MaxDownloadSize {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("download artifact %s: content length %d exceeds 100 MiB limit", candidate.Filename, resp.ContentLength)
	}

	tempFile, err := os.CreateTemp("", "sourcegate-artifact-*")
	if err != nil {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("create temporary artifact file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()
	if err := tempFile.Chmod(0600); err != nil {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("secure temporary artifact file: %w", err)
	}

	digest, err := digestWriter(candidate.DigestAlgorithm)
	if err != nil {
		return report.ArtifactDownloadSummary{}, err
	}
	limited := io.LimitReader(resp.Body, MaxDownloadSize+1)
	written, err := io.Copy(io.MultiWriter(tempFile, digest), limited)
	if err != nil {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("download artifact %s: %w", candidate.Filename, err)
	}
	if written > MaxDownloadSize {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("download artifact %s exceeds 100 MiB limit", candidate.Filename)
	}
	if candidate.ExpectedSize > 0 && written != candidate.ExpectedSize {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("download artifact %s: size mismatch: downloaded %d bytes, expected %d", candidate.Filename, written, candidate.ExpectedSize)
	}
	if err := verifyDigest(candidate, digest.Sum(nil)); err != nil {
		return report.ArtifactDownloadSummary{}, err
	}
	if err := tempFile.Close(); err != nil {
		return report.ArtifactDownloadSummary{}, fmt.Errorf("close temporary artifact file: %w", err)
	}
	if use != nil {
		if err := use(tempPath); err != nil {
			return report.ArtifactDownloadSummary{}, fmt.Errorf("inspect artifact %s: %w", candidate.Filename, err)
		}
	}

	return report.ArtifactDownloadSummary{
		Status:          report.ArtifactDownloadStatusVerified,
		Filename:        candidate.Filename,
		PackageType:     candidate.PackageType,
		DownloadedSize:  written,
		DigestAlgorithm: strings.ToLower(candidate.DigestAlgorithm),
		DigestVerified:  true,
	}, nil
}

func validateCandidate(candidate report.ArtifactCandidate) error {
	if candidate.SelectionError != "" {
		return fmt.Errorf("select install-target artifact: %s", candidate.SelectionError)
	}
	parsed, err := url.Parse(candidate.URL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("artifact %s has invalid download URL", candidate.Filename)
	}
	if strings.TrimSpace(candidate.Filename) == "" {
		return fmt.Errorf("selected artifact filename is unavailable")
	}
	if candidate.ExpectedSize < 0 {
		return fmt.Errorf("artifact %s has invalid expected size", candidate.Filename)
	}
	if candidate.ExpectedSize > MaxDownloadSize {
		return fmt.Errorf("artifact %s expected size %d exceeds 100 MiB limit", candidate.Filename, candidate.ExpectedSize)
	}
	if strings.TrimSpace(candidate.DigestValue) == "" {
		return fmt.Errorf("artifact %s has no trusted registry digest", candidate.Filename)
	}
	_, err = digestWriter(candidate.DigestAlgorithm)
	return err
}

func digestWriter(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported artifact digest algorithm %q", algorithm)
	}
}

func verifyDigest(candidate report.ArtifactCandidate, actual []byte) error {
	expected, err := decodeDigest(candidate.DigestValue, len(actual))
	if err != nil {
		return fmt.Errorf("artifact %s has invalid %s registry digest: %w", candidate.Filename, candidate.DigestAlgorithm, err)
	}
	if subtle.ConstantTimeCompare(expected, actual) != 1 {
		return fmt.Errorf("artifact %s failed %s digest verification", candidate.Filename, strings.ToLower(candidate.DigestAlgorithm))
	}
	return nil
}

func decodeDigest(value string, byteLength int) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == byteLength {
		return decoded, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != byteLength {
		return nil, fmt.Errorf("expected %d digest bytes", byteLength)
	}
	return decoded, nil
}
