package output

import (
	"encoding/json"
	"io"

	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/version"
)

const JSONSchemaVersion = "4"

type JSONReport struct {
	SchemaVersion     string               `json:"schema_version"`
	SourceGateVersion string               `json:"sourcegate_version"`
	InstallExecuted   bool                 `json:"install_executed"`
	Report            report.PackageReport `json:"report"`
}

func RenderJSON(w io.Writer, pkg report.PackageReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(JSONReport{
		SchemaVersion:     JSONSchemaVersion,
		SourceGateVersion: version.Current,
		InstallExecuted:   false,
		Report:            pkg,
	})
}
