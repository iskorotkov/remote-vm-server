package html

import (
	"embed"
)

//nolint:gochecknoglobals
var (
	//go:embed sign-in-completed.html
	SignInCompleted embed.FS
)
