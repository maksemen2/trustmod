package gomod

import (
	"os"

	"golang.org/x/mod/modfile"
)

func ParseGoWorkFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGoWork(path, data)
}

func ParseGoWork(path string, data []byte) ([]string, error) {
	wf, err := modfile.ParseWork(path, data, nil)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(wf.Use))
	for _, use := range wf.Use {
		dirs = append(dirs, use.Path)
	}
	return dirs, nil
}
