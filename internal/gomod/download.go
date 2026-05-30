package gomod

import (
	"context"
	"encoding/json"
	"time"
)

type DownloadInfo struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Info     string `json:"Info"`
	GoMod    string `json:"GoMod"`
	Zip      string `json:"Zip"`
	Dir      string `json:"Dir"`
	Sum      string `json:"Sum"`
	GoModSum string `json:"GoModSum"`
	Error    string `json:"Error"`
}

func Download(ctx context.Context, dir, moduleSpec string, timeout time.Duration) (*DownloadInfo, error) {
	out, err := Go(ctx, dir, timeout, "mod", "download", "-json", moduleSpec)
	if err != nil {
		return nil, err
	}
	var info DownloadInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, err
	}
	return &info, nil
}
