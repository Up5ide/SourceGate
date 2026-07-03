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
	ArtifactInspectionStatusInspected    = "INSPECTED"
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

type ArtifactExecutionSurface struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Name   string `json:"name,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type ArtifactSuspiciousFileType struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type ArtifactBehaviorIndicator struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type ArtifactGeneralRiskSignal struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type ArtifactInspectionSummary struct {
	Status                     string                       `json:"status"`
	ArchiveFormat              string                       `json:"archive_format"`
	FileCount                  int                          `json:"file_count"`
	DirectoryCount             int                          `json:"directory_count"`
	SymlinkCount               int                          `json:"symlink_count"`
	HardlinkCount              int                          `json:"hardlink_count"`
	TotalUncompressedBytes     int64                        `json:"total_uncompressed_bytes"`
	CompressedBytes            int64                        `json:"compressed_bytes"`
	ExpansionRatio             float64                      `json:"expansion_ratio"`
	MaxPathDepth               int                          `json:"max_path_depth"`
	DuplicatePathCount         int                          `json:"duplicate_path_count"`
	NestedArchiveCount         int                          `json:"nested_archive_count"`
	UnsafePathCount            int                          `json:"unsafe_path_count,omitempty"`
	UnsafePathExamples         []string                     `json:"unsafe_path_examples,omitempty"`
	ExecutionSurfaceCount      int                          `json:"execution_surface_count,omitempty"`
	ExecutionSurfaceExamples   []ArtifactExecutionSurface   `json:"execution_surface_examples,omitempty"`
	SuspiciousFileTypeCount    int                          `json:"suspicious_file_type_count,omitempty"`
	SuspiciousFileTypeExamples []ArtifactSuspiciousFileType `json:"suspicious_file_type_examples,omitempty"`
	BehaviorIndicatorCount     int                          `json:"behavior_indicator_count,omitempty"`
	BehaviorIndicatorExamples  []ArtifactBehaviorIndicator  `json:"behavior_indicator_examples,omitempty"`
	GeneralRiskSignalCount     int                          `json:"general_risk_signal_count,omitempty"`
	GeneralRiskSignalExamples  []ArtifactGeneralRiskSignal  `json:"general_risk_signal_examples,omitempty"`
	Paths                      []string                     `json:"-"`
	ExpansionRatioApplicable   bool                         `json:"-"`
}

type ArtifactDeltaSummary struct {
	Status                             string                       `json:"status"`
	PreviousFilename                   string                       `json:"previous_filename,omitempty"`
	PreviousPackageType                string                       `json:"previous_package_type,omitempty"`
	AddedPathCount                     int                          `json:"added_path_count,omitempty"`
	AddedPathExamples                  []string                     `json:"added_path_examples,omitempty"`
	RemovedPathCount                   int                          `json:"removed_path_count,omitempty"`
	RemovedPathExamples                []string                     `json:"removed_path_examples,omitempty"`
	NewExecutionSurfaceCount           int                          `json:"new_execution_surface_count,omitempty"`
	NewExecutionSurfaceExamples        []ArtifactExecutionSurface   `json:"new_execution_surface_examples,omitempty"`
	NewSuspiciousFileTypeCount         int                          `json:"new_suspicious_file_type_count,omitempty"`
	NewSuspiciousFileTypeExamples      []ArtifactSuspiciousFileType `json:"new_suspicious_file_type_examples,omitempty"`
	FileCountDelta                     int                          `json:"file_count_delta,omitempty"`
	UncompressedSizeDeltaBytes         int64                        `json:"uncompressed_size_delta_bytes,omitempty"`
	UncompressedSizeDeltaPercent       int                          `json:"uncompressed_size_delta_percent,omitempty"`
	UncompressedSizeDeltaPercentKnown  bool                         `json:"uncompressed_size_delta_percent_known"`
	PreviousFileCount                  int                          `json:"previous_file_count,omitempty"`
	PreviousTotalUncompressedBytes     int64                        `json:"previous_total_uncompressed_bytes,omitempty"`
	SelectedTotalUncompressedBytes     int64                        `json:"selected_total_uncompressed_bytes,omitempty"`
	PreviousArtifactInspectionError    string                       `json:"previous_artifact_inspection_error,omitempty"`
	PreviousArtifactDownloadStatus     string                       `json:"previous_artifact_download_status,omitempty"`
	PreviousArtifactDigestVerified     bool                         `json:"previous_artifact_digest_verified,omitempty"`
	PreviousArtifactDownloadedSize     int64                        `json:"previous_artifact_downloaded_size,omitempty"`
	PreviousArtifactDigestAlgorithm    string                       `json:"previous_artifact_digest_algorithm,omitempty"`
	PreviousArtifactSelectionError     string                       `json:"previous_artifact_selection_error,omitempty"`
	PreviousArtifactUnavailableMessage string                       `json:"previous_artifact_unavailable_message,omitempty"`
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

type NPMDependencySet struct {
	Dependencies         []string `json:"dependencies,omitempty"`
	OptionalDependencies []string `json:"optional_dependencies,omitempty"`
	PeerDependencies     []string `json:"peer_dependencies,omitempty"`
	DevDependencies      []string `json:"dev_dependencies,omitempty"`
}

type VersionNPMDependencies struct {
	Version           string           `json:"version"`
	PublishedAt       string           `json:"published_at"`
	Dependencies      NPMDependencySet `json:"dependencies"`
	DependenciesKnown bool             `json:"dependencies_known"`
}

type NPMDirectDependencyInspection struct {
	Name                       string            `json:"name"`
	DependencyKind             string            `json:"dependency_kind"`
	RequestedRange             string            `json:"requested_range"`
	Selection                  string            `json:"selection"`
	SelectedVersion            string            `json:"selected_version,omitempty"`
	FetchStatus                string            `json:"fetch_status"`
	FetchError                 string            `json:"fetch_error,omitempty"`
	LifecycleScripts           map[string]string `json:"lifecycle_scripts,omitempty"`
	LifecycleFindings          []string          `json:"lifecycle_findings,omitempty"`
	SuspiciousCommandFindings  []string          `json:"suspicious_command_findings,omitempty"`
	ExactVersionRangeSupported bool              `json:"exact_version_range_supported"`
}

type NPMSourceMetadata struct {
	RepositoryURL                   string `json:"repository_url,omitempty"`
	PreviousRepositoryURL           string `json:"previous_repository_url,omitempty"`
	SelectedGitHead                 string `json:"selected_git_head,omitempty"`
	PreviousGitHead                 string `json:"previous_git_head,omitempty"`
	SelectedPublisher               string `json:"selected_publisher,omitempty"`
	PreviousPublisher               string `json:"previous_publisher,omitempty"`
	RecentReleaseCountInBurstWindow int    `json:"recent_release_count_in_burst_window,omitempty"`
	ReleaseBurstWindowHours         int    `json:"release_burst_window_hours,omitempty"`
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
	EvaluationMode              string                          `json:"evaluation_mode,omitempty"`
	Ecosystem                   string                          `json:"ecosystem"`
	Registry                    string                          `json:"registry"`
	Name                        string                          `json:"name"`
	SelectedVersion             string                          `json:"selected_version"`
	SelectedPublishedAt         string                          `json:"selected_published_at"`
	PreviousPublishedAt         string                          `json:"previous_published_at"`
	Description                 string                          `json:"description"`
	License                     string                          `json:"license"`
	Author                      string                          `json:"author"`
	Maintainers                 []string                        `json:"maintainers"`
	LifecycleScripts            map[string]string               `json:"lifecycle_scripts"`
	LifecycleHistory            []VersionLifecycleScripts       `json:"lifecycle_history"`
	NPMDependencies             NPMDependencySet                `json:"npm_dependencies"`
	NPMDependencyHistory        []VersionNPMDependencies        `json:"npm_dependency_history"`
	NPMDirectDependencies       []NPMDirectDependencyInspection `json:"npm_direct_dependencies,omitempty"`
	NPMDirectDependencyLimit    int                             `json:"npm_direct_dependency_limit,omitempty"`
	NPMDirectDependencyOverflow int                             `json:"npm_direct_dependency_overflow,omitempty"`
	NPMSource                   NPMSourceMetadata               `json:"npm_source"`
	PyPISelectedRelease         PyPIReleaseInfo                 `json:"pypi_selected_release"`
	PyPIReleaseHistory          []PyPIReleaseInfo               `json:"pypi_release_history"`
	ProjectURLs                 []string                        `json:"project_urls"`
	CreatedAt                   string                          `json:"created_at"`
	ModifiedAt                  string                          `json:"modified_at"`
	VersionCount                int                             `json:"version_count"`
	Warnings                    []string                        `json:"warnings"`
	NPMHistory                  HistoryDiagnostics              `json:"npm_history"`
	PyPIHistory                 HistoryDiagnostics              `json:"pypi_history"`
	PyPIProvenance              PyPIProvenanceSummary           `json:"pypi_provenance"`
	PolicySummary               string                          `json:"policy_summary"`
	Decision                    Decision                        `json:"decision"`
	Findings                    []Finding                       `json:"findings"`
	DebugTrace                  []DebugTraceEntry               `json:"debug_trace,omitempty"`
	ArtifactCandidate           ArtifactCandidate               `json:"-"`
	PreviousArtifactCandidate   ArtifactCandidate               `json:"-"`
	ArtifactDownload            *ArtifactDownloadSummary        `json:"artifact_download,omitempty"`
	ArtifactInspection          *ArtifactInspectionSummary      `json:"artifact_inspection,omitempty"`
	ArtifactDelta               *ArtifactDeltaSummary           `json:"artifact_delta,omitempty"`
}
