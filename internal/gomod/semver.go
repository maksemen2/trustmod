package gomod

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

var pseudoVersionRE = regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}$|^v\d+\.\d+\.\d+-[0-9A-Za-z.-]+\.\d{14}-[0-9a-f]{12}$`)

func MajorVersion(version string) int {
	if version == "" {
		return 0
	}
	major := semver.Major(version)
	major = strings.TrimPrefix(major, "v")
	n, _ := strconv.Atoi(major)
	return n
}

func SemverStatus(version string) string {
	if version == "" {
		return "unknown"
	}
	if !semver.IsValid(version) {
		return "non-semver"
	}
	if IsPseudoVersion(version) {
		return "pseudo-version"
	}
	if semver.Prerelease(version) != "" {
		return "pre-release"
	}
	if MajorVersion(version) == 0 {
		return "below-v1"
	}
	return "stable"
}

func IsPseudoVersion(version string) bool {
	return pseudoVersionRE.MatchString(version)
}

func IsPrerelease(version string) bool {
	return semver.IsValid(version) && semver.Prerelease(version) != ""
}

func MajorVersionPathMismatch(modulePath, version string) bool {
	major := MajorVersion(version)
	if major < 2 {
		return false
	}
	if strings.HasPrefix(modulePath, "gopkg.in/") {
		return false
	}
	return !strings.HasSuffix(modulePath, "/v"+strconv.Itoa(major))
}
