package firstrelease

import "github.com/sourcegate/sourcegate/internal/report"

func Check(pkg report.PackageReport) []report.Finding {
	if pkg.VersionCount != 1 {
		return nil
	}

	return []report.Finding{{
		Message: "package has only one published version; first-release packages have limited trust history",
	}}
}
