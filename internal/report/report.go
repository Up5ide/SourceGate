package report

type Decision string

const (
	DecisionInspectOnly Decision = "INSPECT_ONLY"
	DecisionAllow       Decision = "ALLOW"
	DecisionBlock       Decision = "BLOCK"
)

type Finding struct {
	Severity string
	Message  string
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
	CheckID  string
	Status   DebugTraceStatus
	Severity string
	Evidence []string
}

type VersionLifecycleScripts struct {
	Version      string
	PublishedAt  string
	Scripts      map[string]string
	ScriptsKnown bool
}

type PyPIReleaseFile struct {
	Filename            string
	PackageType         string
	PythonVersion       string
	Size                int64
	UploadedAt          string
	RequiresPython      string
	Digests             map[string]string
	Yanked              bool
	YankedReason        string
	ProvenanceChecked   bool
	ProvenanceAvailable bool
	ProvenanceError     string
	ProvenanceScopes    []string
}

type PyPIReleaseInfo struct {
	Version              string
	PublishedAt          string
	Files                []PyPIReleaseFile
	Dependencies         []string
	OptionalDependencies []string
	DependenciesKnown    bool
}

type HistoryDiagnostics struct {
	SelectedVersions          []string
	SkippedLaterVersions      int
	SkippedPrereleaseVersions int
	SkippedMalformedVersions  []string
	SkippedMalformedTimes     []string
	IndeterminateReason       string
}

type PyPIProvenanceSummary struct {
	RequestedScopes        []string
	PythonExecutable       string
	TargetPlatform         string
	PythonVersion          string
	Implementation         string
	ABIs                   []string
	CompatibleTagCount     int
	UsedFallback           bool
	FallbackReason         string
	CheckedCompatibleFiles int
	SkippedNonTargetFiles  int
}

type PackageReport struct {
	Ecosystem           string
	Registry            string
	Name                string
	SelectedVersion     string
	SelectedPublishedAt string
	PreviousPublishedAt string
	Description         string
	License             string
	Author              string
	Maintainers         []string
	LifecycleScripts    map[string]string
	LifecycleHistory    []VersionLifecycleScripts
	PyPISelectedRelease PyPIReleaseInfo
	PyPIReleaseHistory  []PyPIReleaseInfo
	ProjectURLs         []string
	CreatedAt           string
	ModifiedAt          string
	VersionCount        int
	Warnings            []string
	NPMHistory          HistoryDiagnostics
	PyPIHistory         HistoryDiagnostics
	PyPIProvenance      PyPIProvenanceSummary
	PolicySummary       string
	Decision            Decision
	Findings            []Finding
	DebugTrace          []DebugTraceEntry
}
