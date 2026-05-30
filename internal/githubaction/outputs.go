package githubaction

import (
	"fmt"
	"os"

	"github.com/maksemen2/trustmod/internal/fsutil"
)

func SetOutput(name, value string) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		fmt.Printf("%s=%s\n", name, value)
		return nil
	}
	f, err := fsutil.AppendPrivateFile(path)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s=%s\n", name, value)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
