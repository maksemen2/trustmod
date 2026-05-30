package cache

func PathForKey(dir string, parts ...string) string {
	return Key(append([]string{dir}, parts...)...)
}
