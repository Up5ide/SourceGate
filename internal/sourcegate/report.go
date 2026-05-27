package sourcegate

type PackageReport struct {
	Ecosystem     string
	Registry      string
	Name          string
	LatestVersion string
	Description   string
	License       string
	Author        string
	Maintainers   []string
	ProjectURLs   []string
	CreatedAt     string
	ModifiedAt    string
	VersionCount  int
}
