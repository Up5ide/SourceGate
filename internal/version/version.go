package version

const Current = "0.7.0"

func UserAgent() string {
	return "sourcegate/" + Current
}
