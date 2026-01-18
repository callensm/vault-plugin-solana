package version

import "fmt"

var (
	Commit  string
	Name    string
	Version string = "0.0.0"

	HumanVersion = fmt.Sprintf("%s v%s (%s)", Name, Version, Commit)
)
