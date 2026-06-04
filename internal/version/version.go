package version

const Current = "0.6.0"

func UserAgent() string {
	return "sourcegate/" + Current
}
