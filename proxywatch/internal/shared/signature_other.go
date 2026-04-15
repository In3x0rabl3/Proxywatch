//go:build !linux && !darwin && !windows

package shared

func verifyBinaryTrust(exePath string) (string, string) {
	_ = exePath
	return SignatureTrustUnknown, ""
}

func performAuthenticodeVerify(exePath string) (string, string, []string, bool, error) {
	_ = exePath
	return SignatureTrustUnknown, "", nil, false, nil
}
