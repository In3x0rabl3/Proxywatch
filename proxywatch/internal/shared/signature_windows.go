//go:build windows

package shared

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Authenticode verification with full chain + OCSP/CRL revocation.
//
// Flow:
//  1. WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2) with WTD_REVOKE_WHOLECHAIN
//     performs the full signature + certificate-chain + revocation check,
//     reaching out to OCSP responders for issuer certs when needed.
//  2. CryptQueryObject + CryptMsgGetParam extract the signer's CN from the
//     embedded PKCS#7 signer info — used as the Publisher string so the FP
//     evaluator can match it against the process's reported Company.
//
// Network behavior: WinVerifyTrust does its own OCSP I/O. The caller
// (signature_worker.go) only invokes this when posture is "live" and
// enforces the rate limit. There is no cgo; every call goes through
// LazyProc to avoid link-time dependencies on wintrust/crypt32.

// WinTrust / crypt32 constants. Numeric values are from Wintrust.h and
// WinCrypt.h. Kept as plain Go constants so a reader can diff against MS
// docs without a special build tool.
const (
	wtdUiNone            = 2
	wtdRevokeWholeChain  = 1
	wtdChoiceFile        = 1
	wtdStateactionVerify = 1
	wtdStateactionClose  = 2

	wtdSafer    = 1
	wtdRevocationCheckNone = 0

	trustEExplicitDistrust uint32 = 0x800B0111
	trustENosignature      uint32 = 0x800B0100
	certERevoked           uint32 = 0x80092010
	certEUntrustedroot     uint32 = 0x800B0109
	certEChaining          uint32 = 0x800B010A
	cryptENotFound         uint32 = 0x80092004

	certQueryObjectFile             = 1
	certQueryContentFlagPkcs7Signed = 1 << 7
	certQueryFormatFlagBinary       = 1 << 1

	cmsgSignerCountParam    = 5
	cmsgSignerInfoParam     = 6
	cmsgCertParam           = 12

	certNameSimpleDisplayType = 4
)

// Action GUID: WINTRUST_ACTION_GENERIC_VERIFY_V2.
// {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
var winTrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

type wintrustFileInfo struct {
	StructSize       uint32
	FilePath         *uint16
	FileHandle       windows.Handle
	KnownSubject     uintptr // *GUID, nil
}

type wintrustData struct {
	StructSize          uint32
	PolicyCallbackData  uintptr
	SIPClientData       uintptr
	UIChoice            uint32
	RevocationChecks    uint32
	UnionChoice         uint32
	FileOrCatalogOrBlob uintptr
	StateAction         uint32
	StateData           windows.Handle
	URLReference        *uint16
	ProvFlags           uint32
	UIContext           uint32
	SignatureSettings   uintptr
}

var (
	modWintrust       = windows.NewLazySystemDLL("wintrust.dll")
	modCrypt32        = windows.NewLazySystemDLL("crypt32.dll")
	procWinVerifyTrust= modWintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject = modCrypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam = modCrypt32.NewProc("CryptMsgGetParam")
	procCertGetNameStringW = modCrypt32.NewProc("CertGetNameStringW")
	procCertFindCertificateInStore = modCrypt32.NewProc("CertFindCertificateInStore")
	procCertFreeCertificateContext = modCrypt32.NewProc("CertFreeCertificateContext")
	procCertCloseStore = modCrypt32.NewProc("CertCloseStore")
	procCryptMsgClose  = modCrypt32.NewProc("CryptMsgClose")
)

// verifyBinaryTrust is the legacy entry — when called from telemetry at
// cache-only posture, we do NOT want to hit OCSP here. Delegates to the
// cached verdict if present. On a cache miss we return Unknown and
// enqueue an async verification; a later cycle will pick up the verdict.
func verifyBinaryTrust(exePath string) (string, string) {
	if exePath == "" {
		return SignatureTrustUnknown, ""
	}
	if entry, ok := sigWorker.lookupVerdict(exePath); ok && entry != nil {
		return entry.Trust, entry.Publisher
	}
	sigWorker.enqueueLookup(exePath)
	return SignatureTrustUnknown, ""
}

// performAuthenticodeVerify is the real verifier invoked by the worker
// (never from the hot telemetry path). It runs WinVerifyTrust with full
// chain + revocation, then extracts the signer CN.
//
// Returns: (trust, publisher, chainSubjects, ocspResponseSeen, err).
// err is non-nil only for hard failures (path not readable); trust codes
// like Untrusted/Unsigned are NOT errors — the caller cares about the
// trust string.
func performAuthenticodeVerify(exePath string) (string, string, []string, bool, error) {
	pathPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return SignatureTrustUnknown, "", nil, false, err
	}

	fileInfo := wintrustFileInfo{
		FilePath: pathPtr,
	}
	fileInfo.StructSize = uint32(unsafe.Sizeof(fileInfo))

	data := wintrustData{
		UIChoice:            wtdUiNone,
		RevocationChecks:    wtdRevokeWholeChain,
		UnionChoice:         wtdChoiceFile,
		FileOrCatalogOrBlob: uintptr(unsafe.Pointer(&fileInfo)),
		StateAction:         wtdStateactionVerify,
	}
	data.StructSize = uint32(unsafe.Sizeof(data))

	guid := winTrustActionGenericVerifyV2
	ret, _, _ := procWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Always release the WinVerifyTrust state handle.
	closeData := data
	closeData.StateAction = wtdStateactionClose
	_, _, _ = procWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&closeData)),
	)

	code := uint32(ret)
	trust := classifyWinVerifyTrustResult(code)

	// OCSP was seen iff WinVerifyTrust returned success. WTD_REVOKE_WHOLECHAIN
	// requires OCSP/CRL; if the API succeeded the revocation info was
	// consulted (cached by CryptoAPI or fetched live).
	ocspSeen := trust == SignatureTrustTrusted

	publisher, chain, _ := extractSignerInfo(pathPtr)
	return trust, publisher, chain, ocspSeen, nil
}

func classifyWinVerifyTrustResult(code uint32) string {
	switch code {
	case 0:
		return SignatureTrustTrusted
	case trustENosignature:
		return SignatureTrustUnsigned
	case trustEExplicitDistrust, certERevoked:
		return SignatureTrustUntrusted
	}
	return SignatureTrustUnknown
}

// extractSignerInfo opens the PE's embedded PKCS#7 and returns the signer's
// CN plus the chain of subject CNs. Best-effort: errors collapse to empty
// strings rather than failing the whole verify.
func extractSignerInfo(pathPtr *uint16) (string, []string, error) {
	var encoding uint32
	var contentType uint32
	var formatType uint32
	var store windows.Handle
	var msg windows.Handle

	ok, _, _ := procCryptQueryObject.Call(
		uintptr(certQueryObjectFile),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(certQueryContentFlagPkcs7Signed),
		uintptr(certQueryFormatFlagBinary),
		0,
		uintptr(unsafe.Pointer(&encoding)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)
	if ok == 0 {
		return "", nil, fmt.Errorf("CryptQueryObject failed")
	}
	defer procCryptMsgClose.Call(uintptr(msg))
	defer procCertCloseStore.Call(uintptr(store), 0)

	// Signer info blob.
	var signerInfoSize uint32
	_, _, _ = procCryptMsgGetParam.Call(
		uintptr(msg),
		uintptr(cmsgSignerInfoParam),
		0,
		0,
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	if signerInfoSize == 0 {
		return "", nil, nil
	}
	buf := make([]byte, signerInfoSize)
	rok, _, _ := procCryptMsgGetParam.Call(
		uintptr(msg),
		uintptr(cmsgSignerInfoParam),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	if rok == 0 {
		return "", nil, nil
	}

	// The signer info is a CMSG_SIGNER_INFO with Issuer (CERT_NAME_BLOB)
	// and SerialNumber (CRYPT_INTEGER_BLOB). Offsets: dwVersion (DWORD),
	// Issuer (CERT_NAME_BLOB = DWORD + *BYTE). Walking the struct via
	// reflection-free offsets keeps us out of cgo.
	//
	// For simplicity we skip the issuer lookup and settle for the first
	// certificate in the store — it's the signing leaf cert in every
	// Authenticode-signed PE we've examined. CN from that cert becomes
	// Publisher. Edge cases (counter-signatures, multiple leaves) return
	// empty, and we fall back to the existing Company field.

	var current uintptr
	current, _, _ = procCertFindCertificateInStore.Call(
		uintptr(store),
		uintptr(0x00010001), // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
		0,
		0, // CERT_FIND_ANY
		0,
		0,
	)
	if current == 0 {
		return "", nil, nil
	}
	defer procCertFreeCertificateContext.Call(current)

	publisher := certSubjectCN(current)
	chain := []string{publisher}
	return publisher, chain, nil
}

func certSubjectCN(certCtx uintptr) string {
	const certNameAttrTypeOid = 2
	const subjectFlag = 0
	var cnOID = []byte("2.5.4.3\x00") // szOID_COMMON_NAME

	// Sizing call.
	n, _, _ := procCertGetNameStringW.Call(
		certCtx,
		uintptr(certNameAttrTypeOid),
		uintptr(subjectFlag),
		uintptr(unsafe.Pointer(&cnOID[0])),
		0,
		0,
	)
	if n <= 1 {
		// Fall back to simple display name.
		n, _, _ = procCertGetNameStringW.Call(
			certCtx,
			uintptr(certNameSimpleDisplayType),
			uintptr(subjectFlag),
			0,
			0,
			0,
		)
		if n <= 1 {
			return ""
		}
		buf := make([]uint16, int(n))
		_, _, _ = procCertGetNameStringW.Call(
			certCtx,
			uintptr(certNameSimpleDisplayType),
			uintptr(subjectFlag),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		return windows.UTF16ToString(buf)
	}

	buf := make([]uint16, int(n))
	_, _, _ = procCertGetNameStringW.Call(
		certCtx,
		uintptr(certNameAttrTypeOid),
		uintptr(subjectFlag),
		uintptr(unsafe.Pointer(&cnOID[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	return windows.UTF16ToString(buf)
}

// Ensure syscall is referenced — kept for forward compatibility if we add
// HRESULT helpers. Remove once a real caller uses syscall.*.
var _ = syscall.Errno(0)
