package archiveinspect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectTarGzipInventoryWithoutExtraction(t *testing.T) {
	path := writeTarGzip(t, []tarEntry{
		{name: "package/", typeflag: tar.TypeDir},
		{name: "package/index.js", content: []byte("console.log(1)")},
		{name: "package/vendor.zip", content: []byte("nested")},
		{name: "package/bin/tool", typeflag: tar.TypeSymlink, linkname: "../index.js"},
		{name: "package/index-copy.js", typeflag: tar.TypeLink, linkname: "package/index.js"},
	})

	summary, err := Inspect(path, "pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if summary.ArchiveFormat != "tar.gz" || summary.FileCount != 2 || summary.DirectoryCount != 1 || summary.SymlinkCount != 1 || summary.HardlinkCount != 1 {
		t.Fatalf("summary = %+v, want tar.gz inventory counts", summary)
	}
	if summary.NestedArchiveCount != 1 || summary.UnsafePathCount != 0 {
		t.Fatalf("summary = %+v, want nested archive and no unsafe paths", summary)
	}
}

func TestInspectTarGzipDetectsUnsafePaths(t *testing.T) {
	path := writeTarGzip(t, []tarEntry{
		{name: "../escape.js", content: []byte("x")},
		{name: "/absolute.js", content: []byte("x")},
		{name: `C:\temp\evil.js`, content: []byte("x")},
		{name: `\\server\share\evil.js`, content: []byte("x")},
		{name: "dup.js", content: []byte("x")},
		{name: "./dup.js", content: []byte("x")},
		{name: "package/link", typeflag: tar.TypeSymlink, linkname: "../../escape.js"},
		{name: "package/hard", typeflag: tar.TypeLink, linkname: "../../escape.js"},
	})

	summary, err := Inspect(path, "pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if summary.UnsafePathCount != 8 || summary.DuplicatePathCount != 1 {
		t.Fatalf("summary = %+v, want eight unsafe path signals and one duplicate", summary)
	}
	for _, want := range []string{"path traversal", "absolute path", "Windows drive path", "UNC path", "duplicate path", "symlink target escapes", "hardlink target escapes"} {
		if !containsExample(summary.UnsafePathExamples, want) {
			t.Fatalf("unsafe examples = %v, want %q", summary.UnsafePathExamples, want)
		}
	}
}

func TestInspectZipWheelInventoryAndSymlink(t *testing.T) {
	path := writeZip(t, []zipEntry{
		{name: "pkg/__init__.py", content: []byte("x")},
		{name: "pkg/data/archive.tar.gz", content: []byte("nested")},
		{name: "pkg/link", content: []byte("__init__.py"), mode: os.ModeSymlink | 0777},
	})

	summary, err := Inspect(path, "pkg-1.0.0-py3-none-any.whl")
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if summary.ArchiveFormat != "zip" || summary.FileCount != 2 || summary.SymlinkCount != 1 || summary.NestedArchiveCount != 1 || summary.UnsafePathCount != 0 {
		t.Fatalf("summary = %+v, want zip inventory counts", summary)
	}
}

func TestInspectExpansionRatioRequiresLargeUncompressedSize(t *testing.T) {
	path := writeTarGzip(t, []tarEntry{{name: "large.bin", content: bytes.Repeat([]byte{0}, 11*1024*1024)}})

	summary, err := Inspect(path, "pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if !summary.ExpansionRatioApplicable || summary.ExpansionRatio <= 100 {
		t.Fatalf("summary = %+v, want high applicable expansion ratio", summary)
	}
}

func TestInspectRejectsUnsupportedFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("not an archive"), 0600); err != nil {
		t.Fatalf("write unsupported artifact: %v", err)
	}
	if _, err := Inspect(path, "artifact.bin"); err == nil {
		t.Fatalf("Inspect returned nil error")
	}
}

func TestNormalizeArchivePathDetectsNULPath(t *testing.T) {
	_, reasons := normalizeArchivePath("pkg/\x00evil.js")
	if !containsString(reasons, "NUL byte path") {
		t.Fatalf("reasons = %v, want NUL byte path", reasons)
	}
}

type tarEntry struct {
	name     string
	content  []byte
	typeflag byte
	linkname string
}

func writeTarGzip(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.tgz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tgz: %v", err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: typeflag,
			Linkname: entry.linkname,
			Mode:     0600,
		}
		if typeflag == tar.TypeReg {
			header.Size = int64(len(entry.content))
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %s: %v", entry.name, err)
		}
		if len(entry.content) > 0 {
			if _, err := tarWriter.Write(entry.content); err != nil {
				t.Fatalf("write tar content %s: %v", entry.name, err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close tgz: %v", err)
	}
	return path
}

type zipEntry struct {
	name    string
	content []byte
	mode    os.FileMode
}

func writeZip(t *testing.T, entries []zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.whl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		w, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create zip header %s: %v", entry.name, err)
		}
		if _, err := w.Write(entry.content); err != nil {
			t.Fatalf("write zip content %s: %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}
	return path
}

func containsExample(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
