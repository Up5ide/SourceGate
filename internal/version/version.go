package version

const Current = "0.6.5"

func UserAgent() string {
	return "sourcegate/" + Current
}
