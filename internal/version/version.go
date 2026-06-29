package version

import "runtime/debug"

const Current = "0.8.1"

type BuildMetadata struct {
	Commit     string
	CommitDate string
	Modified   string
}

func UserAgent() string {
	return "sourcegate/" + Current
}

func Build() BuildMetadata {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return BuildMetadata{}
	}
	var metadata BuildMetadata
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			metadata.Commit = setting.Value
		case "vcs.time":
			metadata.CommitDate = setting.Value
		case "vcs.modified":
			metadata.Modified = setting.Value
		}
	}
	return metadata
}
