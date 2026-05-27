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
	ProjectURLs         []string
	CreatedAt           string
	ModifiedAt          string
	VersionCount        int
	PolicySummary       string
	Decision            Decision
	Findings            []Finding
}
