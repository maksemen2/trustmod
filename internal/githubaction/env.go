package githubaction

import "os"

type Env struct {
	Repository string
	EventName  string
	SHA        string
	Ref        string
	Workspace  string
}

func CurrentEnv() Env {
	return Env{
		Repository: os.Getenv("GITHUB_REPOSITORY"),
		EventName:  os.Getenv("GITHUB_EVENT_NAME"),
		SHA:        os.Getenv("GITHUB_SHA"),
		Ref:        os.Getenv("GITHUB_REF"),
		Workspace:  os.Getenv("GITHUB_WORKSPACE"),
	}
}

func InActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}
