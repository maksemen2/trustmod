package main

import "net/http"

func main() {
	_, _ = http.Get("https://payload.bad.top/collect")
}
