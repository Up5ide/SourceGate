package report

type Decision string

const (
	DecisionInspectOnly Decision = "INSPECT_ONLY"
	DecisionAllow       Decision = "ALLOW"
	DecisionBlock       Decision = "BLOCK"
)

type Finding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

const (
	ArtifactDownloadStatusVerified       = "DOWNLOADED_VERIFIED"
	ArtifactDownloadStatusSkippedBlocked = "SKIPPED_BLOCKED"
)

type ArtifactCandidate struct {
	SelectionError  string `json:"-"`
	URL             string `json:"-"`
	Filename        string `json:"-"`
	PackageType     string `json:"-"`
	ExpectedSize    int64  `json:"-"`
	DigestAlgorithm string `json:"-"`
	DigestValue     string `json:"-"`
}

type ArtifactDownloadSummary struct {
	Status          string `json:"status"`
	Filename        string `json:"filename,omitempty"`
	PackageType     string `json:"package_type,omitempty"`
	DownloadedSize  int64  `json:"downloaded_size,omitempty"`
	DigestAlgorithm string `json:"digest_algorithm,omitempty"`
	DigestVerified  bool   `json:"digest_verified"`
}

type DebugTraceStatus string

const (
	DebugTraceMatch         DebugTraceStatus = "MATCH"
	DebugTraceNoMatch       DebugTraceStatus = "NO MATCH"
	DebugTraceDisabled      DebugTraceStatus = "DISABLED"
	DebugTraceNotApplicable DebugTraceStatus = "NOT APPLICABLE"
	DebugTraceIndeterminate DebugTraceStatus = "INDETERMINATE"
)

type DebugTraceEntry struct {
	CheckID  string           `json:"check_id"`
	Status   DebugTraceStatus `json:"status"`
	Severity string           `json:"severity"`
	Evidence []string         `json:"evidence"`
}

type VersionLifecycleScripts struct {
	Version      string            `json:"version"`
	PublishedAt  string            `json:"published_at"`
	Scripts      map[string]string `json:"scripts"`
	ScriptsKnown bool              `json:"scripts_known"`
}

type PyPIReleaseFile struct {
	Filename            string            `json:"filename"`
	PackageType         string            `json:"package_type"`
	PythonVersion       string            `json:"python_version"`
	Size                int64             `json:"size"`
	UploadedAt          string            `json:"uploaded_at"`
	RequiresPython      string            `json:"requires_python"`
	Digests             map[string]string `json:"digests"`
	Yanked              bool              `json:"yanked"`
	YankedReason        string            `json:"yanked_reason"`
	URL                 string            `json:"-"`
	ProvenanceChecked   bool              `json:"provenance_checked"`
	ProvenanceAvailable bool              `json:"provenance_available"`
	ProvenanceError     string            `json:"provenance_error"`
	ProvenanceScopes    []string          `json:"provenance_scopes"`
}

type PyPIReleaseInfo struct {
	Version              string            `json:"version"`
	PublishedAt          string            `json:"published_at"`
	Files                []PyPIReleaseFile `json:"files"`
	Dependencies         []string          `json:"dependencies"`
	OptionalDependencies []string          `json:"optional_dependencies"`
	DependenciesKnown    bool              `json:"dependencies_known"`
}

type HistoryDiagnostics struct {
	SelectedVersions          []string `json:"selected_versions"`
	SkippedLaterVersions      int      `json:"skipped_later_versions"`
	SkippedPrereleaseVersions int      `json:"skipped_prerelease_versions"`
	SkippedMalformedVersions  []string `json:"skipped_malformed_versions"`
	SkippedMalformedTimes     []string `json:"skipped_malformed_times"`
	IndeterminateReason       string   `json:"indeterminate_reason"`
}

type PyPIProvenanceSummary struct {
	RequestedScopes        []string `json:"requested_scopes"`
	PythonExecutable       string   `json:"python_executable"`
	TargetPlatform         string   `json:"target_platform"`
	PythonVersion          string   `json:"python_version"`
	Implementation         string   `json:"implementation"`
	ABIs                   []string `json:"abis"`
	CompatibleTagCount     int      `json:"compatible_tag_count"`
	UsedFallback           bool     `json:"used_fallback"`
	FallbackReason         string   `json:"fallback_reason"`
	CompatibilityError     string   `json:"compatibility_error,omitempty"`
	CheckedCompatibleFiles int      `json:"checked_compatible_files"`
	SkippedNonTargetFiles  int      `json:"skipped_non_target_files"`
}

type PackageReport struct {
	Ecosystem           string                    `json:"ecosystem"`
	Registry            string                    `json:"registry"`
	Name                string                    `json:"name"`
	SelectedVersion     string                    `json:"selected_version"`
	SelectedPublishedAt string                    `json:"selected_published_at"`
	PreviousPublishedAt string                    `json:"previous_published_at"`
	Description         string                    `json:"description"`
	License             string                    `json:"license"`
	Author              string                    `json:"author"`
	Maintainers         []string                  `json:"maintainers"`
	LifecycleScripts    map[string]string         `json:"lifecycle_scripts"`
	LifecycleHistory    []VersionLifecycleScripts `json:"lifecycle_history"`
	PyPISelectedRelease PyPIReleaseInfo           `json:"pypi_selected_release"`
	PyPIReleaseHistory  []PyPIReleaseInfo         `json:"pypi_release_history"`
	ProjectURLs         []string                  `json:"project_urls"`
	CreatedAt           string                    `json:"created_at"`
	ModifiedAt          string                    `json:"modified_at"`
	VersionCount        int                       `json:"version_count"`
	Warnings            []string                  `json:"warnings"`
	NPMHistory          HistoryDiagnostics        `json:"npm_history"`
	PyPIHistory         HistoryDiagnostics        `json:"pypi_history"`
	PyPIProvenance      PyPIProvenanceSummary     `json:"pypi_provenance"`
	PolicySummary       string                    `json:"policy_summary"`
	Decision            Decision                  `json:"decision"`
	Findings            []Finding                 `json:"findings"`
	DebugTrace          []DebugTraceEntry         `json:"debug_trace,omitempty"`
	ArtifactCandidate   ArtifactCandidate         `json:"-"`
	ArtifactDownload    *ArtifactDownloadSummary  `json:"artifact_download,omitempty"`
}
