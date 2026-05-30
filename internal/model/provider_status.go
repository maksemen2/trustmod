package model

const (
	ProviderStatusOK                        = "ok"
	ProviderStatusDisabled                  = "disabled"
	ProviderStatusNotRequested              = "not_requested"
	ProviderStatusSkippedPrivate            = "skipped_private"
	ProviderStatusSkippedNoPublicModules    = "skipped_no_public_modules"
	ProviderStatusSkippedNoEligibleVersions = "skipped_no_eligible_versions"
	ProviderStatusSkippedUnsupportedHost    = "skipped_unsupported_host"
	ProviderStatusSkippedNoProviderData     = "skipped_no_provider_data"
	ProviderStatusUnavailable               = "unavailable"
	ProviderStatusRateLimited               = "rate_limited"
	ProviderStatusTimeout                   = "timeout"
	ProviderStatusError                     = "error"
	ProviderStatusCancelled                 = "cancelled"
	ProviderStatusOfflineCacheHit           = "offline_cache_hit"
	ProviderStatusOfflineCacheMiss          = "offline_cache_miss"
)

func ProviderStatusIsSuccess(status string) bool {
	return status == ProviderStatusOK || status == ProviderStatusOfflineCacheHit
}

func ProviderStatusCountsAsError(status string) bool {
	switch status {
	case ProviderStatusUnavailable,
		ProviderStatusRateLimited,
		ProviderStatusTimeout,
		ProviderStatusError,
		ProviderStatusCancelled,
		ProviderStatusOfflineCacheMiss:
		return true
	default:
		return false
	}
}

func ProviderStatusSatisfiesRequirement(status string) bool {
	switch status {
	case ProviderStatusOK,
		ProviderStatusOfflineCacheHit,
		ProviderStatusSkippedNoPublicModules,
		ProviderStatusSkippedNoEligibleVersions,
		ProviderStatusSkippedUnsupportedHost,
		ProviderStatusSkippedNoProviderData:
		return true
	default:
		return false
	}
}
