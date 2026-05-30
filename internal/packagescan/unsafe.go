package packagescan

func IsMemorySensitiveCapability(name string) bool {
	return name == "unsafe" || name == "cgo"
}
