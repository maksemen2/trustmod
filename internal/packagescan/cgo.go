package packagescan

func IsNativeCapability(name string) bool {
	return name == "cgo" || name == "unsafe" || name == "syscall"
}
