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
}

type PyPIReleaseInfo struct {
	Version           string
	PublishedAt       string
	Files             []PyPIReleaseFile
	Dependencies      []string
	DependenciesKnown bool
}

type PackageReport struct {
	Ecosystem           string
	Registry            string
	Name                string
	LatestVersion       string
	LatestPublishedAt   string
	PreviousPublishedAt string
	Description         string
	License             string
	Author              string
	Maintainers         []string
	LifecycleScripts    map[string]string
	LifecycleHistory    []VersionLifecycleScripts
	PyPILatestRelease   PyPIReleaseInfo
	PyPIReleaseHistory  []PyPIReleaseInfo
	ProjectURLs         []string
	CreatedAt           string
	ModifiedAt          string
	VersionCount        int
	PolicySummary       string
	Decision            Decision
	Findings            []Finding
}
