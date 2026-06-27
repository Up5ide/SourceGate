package version

const Current = "0.7.1"

func UserAgent() string {
	return "sourcegate/" + Current
}
