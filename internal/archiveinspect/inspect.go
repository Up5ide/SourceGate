package archiveinspect

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

const minExpansionRatioBytes int64 = 10 * 1024 * 1024

func Inspect(artifactPath, filename string) (report.ArtifactInspectionSummary, error) {
	stat, err := os.Stat(artifactPath)
	if err != nil {
		return report.ArtifactInspectionSummary{}, fmt.Errorf("inspect artifact: stat temporary artifact: %w", err)
	}

	format, err := detectFormat(artifactPath, filename)
	if err != nil {
		return report.ArtifactInspectionSummary{}, err
	}

	inspector := archiveInspector{
		summary: report.ArtifactInspectionSummary{
			Status:          report.ArtifactInspectionStatusInspected,
			ArchiveFormat:   format,
			CompressedBytes: stat.Size(),
		},
		seen: make(map[string]struct{}),
	}

	switch format {
	case "tar.gz":
		if err := inspector.inspectTarGzip(artifactPath); err != nil {
			return report.ArtifactInspectionSummary{}, err
		}
	case "zip":
		if err := inspector.inspectZip(artifactPath); err != nil {
			return report.ArtifactInspectionSummary{}, err
		}
	default:
		return report.ArtifactInspectionSummary{}, fmt.Errorf("unsupported artifact archive format %q", format)
	}

	if inspector.summary.CompressedBytes > 0 && inspector.summary.TotalUncompressedBytes >= minExpansionRatioBytes {
		inspector.summary.ExpansionRatioApplicable = true
		inspector.summary.ExpansionRatio = float64(inspector.summary.TotalUncompressedBytes) / float64(inspector.summary.CompressedBytes)
	}
	inspector.summary.UnsafePathCount = inspector.unsafeCount
	inspector.summary.UnsafePathExamples = append([]string(nil), inspector.unsafeExamples...)
	return inspector.summary, nil
}

type archiveInspector struct {
	summary        report.ArtifactInspectionSummary
	seen           map[string]struct{}
	unsafeCount    int
	unsafeExamples []string
}

func (inspector *archiveInspector) inspectTarGzip(artifactPath string) error {
	file, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("inspect tar.gz artifact: %w", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("inspect tar.gz artifact: open gzip stream: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect tar.gz artifact: read tar header: %w", err)
		}
		inspector.recordTarEntry(header)
	}
}

func (inspector *archiveInspector) inspectZip(artifactPath string) error {
	reader, err := zip.OpenReader(artifactPath)
	if err != nil {
		return fmt.Errorf("inspect zip artifact: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if err := inspector.recordZipEntry(file); err != nil {
			return err
		}
	}
	return nil
}

func (inspector *archiveInspector) recordTarEntry(header *tar.Header) {
	normalized, ok := inspector.recordPath(header.Name)
	switch header.Typeflag {
	case tar.TypeDir:
		inspector.summary.DirectoryCount++
	case tar.TypeSymlink:
		inspector.summary.SymlinkCount++
		inspector.recordLinkTarget("symlink", normalized, header.Name, header.Linkname, ok)
	case tar.TypeLink:
		inspector.summary.HardlinkCount++
		inspector.recordLinkTarget("hardlink", normalized, header.Name, header.Linkname, ok)
	case tar.TypeReg, tar.TypeRegA:
		inspector.summary.FileCount++
		inspector.addUncompressedBytes(header.Size)
		if isNestedArchive(normalized) {
			inspector.summary.NestedArchiveCount++
		}
	default:
		inspector.addUncompressedBytes(header.Size)
	}
}

func (inspector *archiveInspector) recordZipEntry(file *zip.File) error {
	normalized, ok := inspector.recordPath(file.Name)
	mode := file.FileInfo().Mode()
	switch {
	case file.FileInfo().IsDir():
		inspector.summary.DirectoryCount++
	case mode&os.ModeSymlink != 0:
		inspector.summary.SymlinkCount++
		target, err := readZipSymlinkTarget(file)
		if err != nil {
			return err
		}
		inspector.recordLinkTarget("symlink", normalized, file.Name, target, ok)
	default:
		inspector.summary.FileCount++
		inspector.addUncompressedBytesFromUint(file.UncompressedSize64)
		if isNestedArchive(normalized) {
			inspector.summary.NestedArchiveCount++
		}
	}
	return nil
}

func (inspector *archiveInspector) recordPath(name string) (string, bool) {
	normalized, reasons := normalizeArchivePath(name)
	for _, reason := range reasons {
		inspector.addUnsafe(fmt.Sprintf("%s: %s", reason, displayPath(name)))
	}
	if normalized != "" {
		if _, exists := inspector.seen[normalized]; exists {
			inspector.summary.DuplicatePathCount++
			inspector.addUnsafe("duplicate path: " + displayPath(name))
		} else {
			inspector.seen[normalized] = struct{}{}
		}
		if depth := pathDepth(normalized); depth > inspector.summary.MaxPathDepth {
			inspector.summary.MaxPathDepth = depth
		}
	}
	return normalized, len(reasons) == 0
}

func (inspector *archiveInspector) recordLinkTarget(kind, normalizedName, originalName, target string, pathOK bool) {
	if strings.TrimSpace(target) == "" {
		return
	}
	if !linkTargetStaysInRoot(normalizedName, target, pathOK) {
		inspector.addUnsafe(fmt.Sprintf("%s target escapes archive root: %s -> %s", kind, displayPath(originalName), displayPath(target)))
	}
}

func (inspector *archiveInspector) addUnsafe(example string) {
	const maxUnsafeExamples = 8
	inspector.unsafeCount++
	if len(inspector.unsafeExamples) < maxUnsafeExamples {
		inspector.unsafeExamples = append(inspector.unsafeExamples, example)
	}
}

func (inspector *archiveInspector) addUncompressedBytes(size int64) {
	if size <= 0 {
		return
	}
	if inspector.summary.TotalUncompressedBytes > math.MaxInt64-size {
		inspector.summary.TotalUncompressedBytes = math.MaxInt64
		return
	}
	inspector.summary.TotalUncompressedBytes += size
}

func (inspector *archiveInspector) addUncompressedBytesFromUint(size uint64) {
	if size > math.MaxInt64 {
		inspector.summary.TotalUncompressedBytes = math.MaxInt64
		return
	}
	inspector.addUncompressedBytes(int64(size))
}

func detectFormat(artifactPath, filename string) (string, error) {
	lowerName := strings.ToLower(filename)
	if strings.HasSuffix(lowerName, ".whl") || strings.HasSuffix(lowerName, ".zip") {
		return "zip", nil
	}
	if strings.HasSuffix(lowerName, ".tar.gz") || strings.HasSuffix(lowerName, ".tgz") {
		return "tar.gz", nil
	}

	file, err := os.Open(artifactPath)
	if err != nil {
		return "", fmt.Errorf("detect artifact archive format: %w", err)
	}
	defer file.Close()

	signature := make([]byte, 4)
	n, _ := io.ReadFull(file, signature)
	switch {
	case n >= 4 && string(signature[:4]) == "PK\x03\x04":
		return "zip", nil
	case n >= 2 && signature[0] == 0x1f && signature[1] == 0x8b:
		return "tar.gz", nil
	default:
		return "", fmt.Errorf("unsupported artifact archive format for %s", filename)
	}
}

func normalizeArchivePath(name string) (string, []string) {
	var reasons []string
	if strings.ContainsRune(name, 0) {
		reasons = append(reasons, "NUL byte path")
	}
	if strings.TrimSpace(name) == "" {
		reasons = append(reasons, "empty path")
	}
	if isAbsoluteArchivePath(name) {
		reasons = append(reasons, "absolute path")
	}
	if hasWindowsDrivePath(name) {
		reasons = append(reasons, "Windows drive path")
	}
	if hasUNCPath(name) {
		reasons = append(reasons, "UNC path")
	}

	slashed := filepath.ToSlash(name)
	cleaned := path.Clean(slashed)
	cleaned = strings.TrimPrefix(cleaned, "./")
	if cleaned == "." {
		cleaned = ""
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		reasons = append(reasons, "path traversal")
	}
	return cleaned, reasons
}

func linkTargetStaysInRoot(normalizedName, target string, pathOK bool) bool {
	if !pathOK || normalizedName == "" {
		return false
	}
	if strings.TrimSpace(target) == "" ||
		strings.ContainsRune(target, 0) ||
		isAbsoluteArchivePath(target) ||
		hasWindowsDrivePath(target) ||
		hasUNCPath(target) {
		return false
	}
	base := path.Dir(normalizedName)
	if base == "." {
		base = ""
	}
	joined := path.Clean(path.Join(base, filepath.ToSlash(target)))
	return joined != ".." && !strings.HasPrefix(joined, "../")
}

func isAbsoluteArchivePath(name string) bool {
	return strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\")
}

func hasWindowsDrivePath(name string) bool {
	if len(name) < 2 {
		return false
	}
	letter := name[0]
	return ((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')) &&
		name[1] == ':'
}

func hasUNCPath(name string) bool {
	return strings.HasPrefix(name, `\\`) || strings.HasPrefix(name, "//")
}

func pathDepth(normalized string) int {
	trimmed := strings.Trim(normalized, "/")
	if trimmed == "" {
		return 0
	}
	return len(strings.Split(trimmed, "/"))
}

func isNestedArchive(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".zip") ||
		strings.HasSuffix(lower, ".whl") ||
		strings.HasSuffix(lower, ".tar") ||
		strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".tgz") ||
		strings.HasSuffix(lower, ".jar")
}

func readZipSymlinkTarget(file *zip.File) (string, error) {
	if file.UncompressedSize64 > 4096 {
		return "", fmt.Errorf("inspect zip artifact: symlink %s target is too large", file.Name)
	}
	reader, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("inspect zip artifact: open symlink %s: %w", file.Name, err)
	}
	defer reader.Close()
	target, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("inspect zip artifact: read symlink %s: %w", file.Name, err)
	}
	return string(target), nil
}

func displayPath(value string) string {
	const maxDisplayPath = 160
	value = strings.ReplaceAll(value, "\x00", "\\0")
	if len(value) <= maxDisplayPath {
		return value
	}
	return value[:maxDisplayPath] + "..."
}
