package main

import "net/http"

const defaultBotAPIServer = "https://api.telegram.org"

func main() {
	_, _ = http.Get(defaultBotAPIServer + "/bot123/sendMessage")
}
