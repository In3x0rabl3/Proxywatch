//go:build !linux && !darwin

package shared

// LookupPackageOwner stubs out on non-Linux platforms. macOS pkgutil and
// Windows MSI enumeration are separate verifier implementations tracked
// under Phase 6b.
func LookupPackageOwner(exePath string) string {
	_ = exePath
	return ""
}
