package archiveinspect

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/sourcegate/sourcegate/internal/report"
)

const minExpansionRatioBytes int64 = 10 * 1024 * 1024
const maxMetadataFileBytes int64 = 256 * 1024
const maxMetadataTotalBytes int64 = 1024 * 1024
const maxExecutionSurfaceExamples = 12

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
	summary           report.ArtifactInspectionSummary
	seen              map[string]struct{}
	unsafeCount       int
	unsafeExamples    []string
	metadataBytesRead int64
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
		if err := inspector.recordTarEntry(header, tarReader); err != nil {
			return err
		}
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

func (inspector *archiveInspector) recordTarEntry(header *tar.Header, reader *tar.Reader) error {
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
		inspector.inspectPathExecutionSurfaces(normalized)
		if inspector.shouldReadMetadata(normalized, header.Size) {
			content, err := readTarMetadata(reader, header.Size)
			if err != nil {
				return err
			}
			inspector.metadataBytesRead += int64(len(content))
			inspector.inspectMetadataExecutionSurfaces(normalized, content)
		}
	default:
		inspector.addUncompressedBytes(header.Size)
	}
	return nil
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
		inspector.inspectPathExecutionSurfaces(normalized)
		if inspector.shouldReadMetadata(normalized, uintToInt64(file.UncompressedSize64)) {
			content, err := readZipMetadata(file)
			if err != nil {
				return err
			}
			inspector.metadataBytesRead += int64(len(content))
			inspector.inspectMetadataExecutionSurfaces(normalized, content)
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

func (inspector *archiveInspector) addExecutionSurface(surface report.ArtifactExecutionSurface) {
	inspector.summary.ExecutionSurfaceCount++
	surface.Path = displayPath(surface.Path)
	surface.Name = displayText(surface.Name)
	surface.Detail = displayText(surface.Detail)
	if len(inspector.summary.ExecutionSurfaceExamples) < maxExecutionSurfaceExamples {
		inspector.summary.ExecutionSurfaceExamples = append(inspector.summary.ExecutionSurfaceExamples, surface)
	}
}

func (inspector *archiveInspector) inspectPathExecutionSurfaces(normalized string) {
	if normalized == "" {
		return
	}
	lower := strings.ToLower(normalized)
	base := strings.ToLower(path.Base(normalized))
	switch base {
	case "binding.gyp":
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{Type: "npm_native_build_hint", Path: normalized, Name: "binding.gyp"})
	case "setup.py", "setup.cfg":
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{Type: "pypi_build_file", Path: normalized, Name: base})
	case "makefile", "cmakelists.txt", "configure":
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{Type: "build_file", Path: normalized, Name: base})
	}
	if strings.HasSuffix(lower, ".pth") {
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{Type: "pypi_startup_file", Path: normalized, Name: path.Base(normalized)})
	}
	if strings.Contains(lower, ".data/scripts/") {
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{Type: "pypi_script", Path: normalized, Name: path.Base(normalized)})
	}
	if isScriptFile(lower) {
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{Type: "script_file", Path: normalized, Name: path.Base(normalized)})
	}
}

func (inspector *archiveInspector) inspectMetadataExecutionSurfaces(normalized string, content []byte) {
	base := strings.ToLower(path.Base(normalized))
	switch base {
	case "package.json":
		inspector.inspectPackageJSON(normalized, content)
	case "pyproject.toml":
		inspector.inspectPyProject(normalized, content)
	case "entry_points.txt":
		inspector.inspectEntryPoints(normalized, content)
	}
}

func (inspector *archiveInspector) inspectPackageJSON(normalized string, content []byte) {
	var metadata npmPackageMetadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		return
	}
	for _, name := range sortedMapKeys(metadata.Scripts) {
		if _, ok := npmInstallLifecycleScripts[strings.ToLower(name)]; !ok {
			continue
		}
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{
			Type:   "npm_lifecycle_script",
			Path:   normalized,
			Name:   name,
			Detail: metadata.Scripts[name],
		})
	}
	for _, entry := range npmBinEntries(metadata.Bin) {
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{
			Type:   "npm_bin",
			Path:   normalized,
			Name:   entry.name,
			Detail: entry.target,
		})
	}
	inspector.inspectNPMNativeHints(normalized, metadata)
}

func (inspector *archiveInspector) inspectNPMNativeHints(normalized string, metadata npmPackageMetadata) {
	for _, dependencyMap := range []map[string]string{metadata.Dependencies, metadata.OptionalDependencies, metadata.DevDependencies} {
		for _, name := range sortedMapKeys(dependencyMap) {
			if _, ok := npmNativeBuildHints[strings.ToLower(name)]; ok {
				inspector.addExecutionSurface(report.ArtifactExecutionSurface{
					Type:   "npm_native_build_hint",
					Path:   normalized,
					Name:   name,
					Detail: "dependency",
				})
			}
		}
	}
	for _, scriptName := range sortedMapKeys(metadata.Scripts) {
		for _, token := range commandTokens(metadata.Scripts[scriptName]) {
			if _, ok := npmNativeBuildHints[token]; ok {
				inspector.addExecutionSurface(report.ArtifactExecutionSurface{
					Type:   "npm_native_build_hint",
					Path:   normalized,
					Name:   token,
					Detail: "script " + scriptName,
				})
			}
		}
	}
}

func (inspector *archiveInspector) inspectPyProject(normalized string, content []byte) {
	lines := strings.Split(string(content), "\n")
	inBuildSystem := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(stripTOMLComment(line))
		lower := strings.ToLower(trimmed)
		switch {
		case lower == "[build-system]":
			inBuildSystem = true
			inspector.addExecutionSurface(report.ArtifactExecutionSurface{
				Type:   "pypi_build_file",
				Path:   normalized,
				Name:   "pyproject.toml",
				Detail: "build-system",
			})
		case strings.HasPrefix(lower, "[") && strings.HasSuffix(lower, "]"):
			inBuildSystem = false
		case inBuildSystem && strings.HasPrefix(lower, "build-backend"):
			inspector.addExecutionSurface(report.ArtifactExecutionSurface{
				Type:   "pypi_build_backend",
				Path:   normalized,
				Name:   "build-backend",
				Detail: trimmed,
			})
		}
	}
}

func (inspector *archiveInspector) inspectEntryPoints(normalized string, content []byte) {
	section := ""
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")))
			continue
		}
		if section != "console_scripts" && section != "gui_scripts" {
			continue
		}
		name := trimmed
		if index := strings.Index(trimmed, "="); index >= 0 {
			name = strings.TrimSpace(trimmed[:index])
		}
		if name == "" {
			continue
		}
		inspector.addExecutionSurface(report.ArtifactExecutionSurface{
			Type:   "pypi_entry_point",
			Path:   normalized,
			Name:   name,
			Detail: section,
		})
	}
}

func (inspector *archiveInspector) shouldReadMetadata(normalized string, size int64) bool {
	if normalized == "" || size < 0 || size > maxMetadataFileBytes {
		return false
	}
	if inspector.metadataBytesRead > maxMetadataTotalBytes-size {
		return false
	}
	base := strings.ToLower(path.Base(normalized))
	return base == "package.json" || base == "pyproject.toml" || base == "entry_points.txt"
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

func isScriptFile(lowerName string) bool {
	return strings.HasSuffix(lowerName, ".sh") ||
		strings.HasSuffix(lowerName, ".bash") ||
		strings.HasSuffix(lowerName, ".zsh") ||
		strings.HasSuffix(lowerName, ".bat") ||
		strings.HasSuffix(lowerName, ".cmd") ||
		strings.HasSuffix(lowerName, ".ps1")
}

func readTarMetadata(reader *tar.Reader, size int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, size))
	if err != nil {
		return nil, fmt.Errorf("inspect tar.gz artifact: read metadata file: %w", err)
	}
	if int64(len(content)) != size {
		return nil, fmt.Errorf("inspect tar.gz artifact: metadata file ended early")
	}
	return content, nil
}

func readZipMetadata(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("inspect zip artifact: open metadata %s: %w", file.Name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, maxMetadataFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("inspect zip artifact: read metadata %s: %w", file.Name, err)
	}
	if int64(len(content)) > maxMetadataFileBytes {
		return nil, fmt.Errorf("inspect zip artifact: metadata %s exceeds read limit", file.Name)
	}
	return content, nil
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

func displayText(value string) string {
	const maxDisplayText = 160
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= maxDisplayText {
		return value
	}
	return value[:maxDisplayText] + "..."
}

type npmPackageMetadata struct {
	Scripts              map[string]string `json:"scripts"`
	Bin                  json.RawMessage   `json:"bin"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

type npmBinEntry struct {
	name   string
	target string
}

var npmInstallLifecycleScripts = map[string]struct{}{
	"preinstall":  {},
	"install":     {},
	"postinstall": {},
	"prepublish":  {},
	"prepare":     {},
	"preprepare":  {},
	"postprepare": {},
}

var npmNativeBuildHints = map[string]struct{}{
	"node-gyp":         {},
	"prebuild-install": {},
	"node-pre-gyp":     {},
	"cmake-js":         {},
}

func npmBinEntries(raw json.RawMessage) []npmBinEntry {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var target string
	if err := json.Unmarshal(raw, &target); err == nil {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil
		}
		return []npmBinEntry{{name: "bin", target: target}}
	}
	var entries map[string]string
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	names := sortedMapKeys(entries)
	result := make([]npmBinEntry, 0, len(names))
	for _, name := range names {
		target := strings.TrimSpace(entries[name])
		if target == "" {
			continue
		}
		result = append(result, npmBinEntry{name: name, target: target})
	}
	return result
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func commandTokens(command string) []string {
	return strings.FieldsFunc(strings.ToLower(command), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_'
	})
}

func stripTOMLComment(line string) string {
	if index := strings.Index(line, "#"); index >= 0 {
		return line[:index]
	}
	return line
}

func uintToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}
