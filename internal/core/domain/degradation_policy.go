package domain

import "strings"

// DegradationPolicyMode enumerates supported degradation behaviors for cache-dependent flows.
type DegradationPolicyMode string

const (
	// DegradationPolicyModeLenient allows operations to proceed when revocation caches are cold or unavailable.
	DegradationPolicyModeLenient DegradationPolicyMode = "lenient"
	// DegradationPolicyModeStrict rejects operations whenever revocation data cannot be confirmed locally.
	DegradationPolicyModeStrict DegradationPolicyMode = "strict"
)

// DegradationReason captures the context for which a fallback decision is evaluated.
type DegradationReason string

const (
	// DegradationReasonCacheMiss indicates the cache lacks an entry for the evaluated subject or token.
	DegradationReasonCacheMiss DegradationReason = "cache_miss"
	// DegradationReasonCacheStale indicates cached data is older than the acceptable freshness window.
	DegradationReasonCacheStale DegradationReason = "cache_stale"
	// DegradationReasonSessionRepositoryUnavailable denotes backend lookups failed for session metadata.
	DegradationReasonSessionRepositoryUnavailable DegradationReason = "session_repository_unavailable"
	// DegradationReasonSessionLookupFailure denotes session lookups failed due to infrastructure errors.
	DegradationReasonSessionLookupFailure DegradationReason = "session_lookup_failure"
	// DegradationReasonRevocationCacheUnavailable denotes redis revocation lookups failed or timed out.
	DegradationReasonRevocationCacheUnavailable DegradationReason = "revocation_cache_unavailable"
)

// DegradationPolicy centralises how the service responds when revocation data is missing or stale.
type DegradationPolicy struct {
	mode DegradationPolicyMode
}

// NewDegradationPolicy constructs a policy with the provided mode, defaulting to lenient when unspecified.
func NewDegradationPolicy(mode DegradationPolicyMode) DegradationPolicy {
	if mode != DegradationPolicyModeStrict {
		mode = DegradationPolicyModeLenient
	}
	return DegradationPolicy{mode: mode}
}

// ParseDegradationPolicyMode normalises textual input into a supported policy mode.
func ParseDegradationPolicyMode(value string) DegradationPolicyMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(DegradationPolicyModeStrict):
		return DegradationPolicyModeStrict
	default:
		return DegradationPolicyModeLenient
	}
}

// Mode returns the underlying policy mode.
func (p DegradationPolicy) Mode() DegradationPolicyMode {
	return p.mode
}

// IsStrict indicates whether the policy rejects degraded states.
func (p DegradationPolicy) IsStrict() bool {
	return p.mode == DegradationPolicyModeStrict
}

// IsLenient indicates whether the policy permits degraded states.
func (p DegradationPolicy) IsLenient() bool {
	return !p.IsStrict()
}

// AllowsFallback determines if the policy permits continuing when the supplied reason occurs.
func (p DegradationPolicy) AllowsFallback(reason DegradationReason) bool {
	return p.IsLenient()
}
