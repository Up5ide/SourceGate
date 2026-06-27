package version

const Current = "0.7.2"

func UserAgent() string {
	return "sourcegate/" + Current
}
