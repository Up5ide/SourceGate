package version

const Current = "0.7.3"

func UserAgent() string {
	return "sourcegate/" + Current
}
