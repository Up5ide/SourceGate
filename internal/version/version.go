package version

const Current = "0.5.2"

func UserAgent() string {
	return "sourcegate/" + Current
}
