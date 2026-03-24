package bloodhound

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
)

// Runtime BloodHound upload configuration is keystore/runtime-config driven.
// Environment variables remain as a fallback for compatibility.
// Required:
//   - BLOODHOUND_API_URL
//   - BLOODHOUND_API_TOKEN
//
// Optional (required for HMAC mode):
//   - BLOODHOUND_API_TOKEN_ID (or BLOODHOUND_API_ID alias)
var (
	BloodhoundAPIURL     = ""
	BloodhoundAPIToken   = "" // HMAC token secret or bearer JWT
	BloodhoundAPITokenID = "" // HMAC token id; leave empty to use bearer
	client               = &http.Client{
		Timeout: 30 * time.Second,
		// Signed requests must not follow redirects automatically because the
		// redirected URI will not match the original signature.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func init() {
	refreshConfigFromRuntime()
}

// fileUploadJobResponse matches /api/v2/file-upload/start response.
// The API nests the job object under a data field and uses an integer id.
type fileUploadJobResponse struct {
	Data struct {
		ID int `json:"id"`
	} `json:"data"`
}

// UploadIfConfigured uploads the given JSON payload to BloodHound via the file upload API.
// Returns nil if upload is skipped (no token) or on success; otherwise returns an error.
func UploadIfConfigured(filename string, payload Payload) error {
	refreshConfigFromRuntime()

	if BloodhoundAPIURL == "" || BloodhoundAPIToken == "" {
		return nil // not configured; skip
	}
	normalizedURL, err := validateBloodhoundAPIURL(BloodhoundAPIURL)
	if err != nil {
		return err
	}
	BloodhoundAPIURL = normalizedURL

	tmpDir := proxywatchTempDir()
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return fmt.Errorf("tmpdir: %w", err)
	}
	tmpFile, err := os.CreateTemp(tmpDir, "pw-bh-*.json")
	if err != nil {
		return fmt.Errorf("tmpfile: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("tmpfile close: %w", err)
	}
	defer os.Remove(tmpPath)
	if err := WriteJSON(tmpPath, payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	jobID, err := startUploadJob()
	if err != nil {
		return fmt.Errorf("start upload job: %w", err)
	}

	if err := uploadFile(jobID, tmpPath, filename); err != nil {
		return fmt.Errorf("upload file: %w", err)
	}

	if err := endUploadJob(jobID); err != nil {
		return fmt.Errorf("end upload job: %w", err)
	}

	return nil
}

func signOrBearerWithKeyMode(req *http.Request, body []byte, decodedKey bool) error {
	if BloodhoundAPITokenID == "" {
		// Prevent a confusing 401 when users provide an HMAC token key without token id.
		if looksLikeTokenKey(BloodhoundAPIToken) && !looksLikeJWT(BloodhoundAPIToken) {
			return fmt.Errorf("BLOODHOUND_API_TOKEN_ID (or BLOODHOUND_API_ID) is required when using an API token key")
		}
		req.Header.Set("Authorization", "Bearer "+BloodhoundAPIToken)
		return nil
	}

	// HMAC signature mode (API key + ID) per BloodHound docs:
	// 1) opKey   = HMAC(key, METHOD+URI)
	// 2) dateKey = HMAC(opKey, RequestDate[:13])  // YYYY-MM-DDTHH
	// 3) sig     = HMAC(dateKey, body)            // body may be empty
	reqDate := time.Now().Format(time.RFC3339)
	req.Header.Set("RequestDate", reqDate)
	req.Header.Set("Authorization", "bhesignature "+BloodhoundAPITokenID)

	keyBytes := []byte(BloodhoundAPIToken)
	if decodedKey {
		decoded, err := base64.StdEncoding.DecodeString(BloodhoundAPIToken)
		if err != nil || len(decoded) == 0 {
			return fmt.Errorf("invalid base64 api token key: %w", err)
		}
		keyBytes = decoded
	}

	// Step 1: METHOD + URI (no delimiter)
	opDig := hmac.New(sha256.New, keyBytes)
	opDig.Write([]byte(strings.ToUpper(req.Method) + req.URL.RequestURI()))
	opKey := opDig.Sum(nil)

	// Step 2: hour-precision timestamp
	ts := reqDate
	if len(ts) > 13 {
		ts = ts[:13]
	}
	dateDig := hmac.New(sha256.New, opKey)
	dateDig.Write([]byte(ts))
	dateKey := dateDig.Sum(nil)

	// Step 3: body (can be empty)
	bodyDig := hmac.New(sha256.New, dateKey)
	if len(body) > 0 {
		bodyDig.Write(body)
	}
	signature := base64.StdEncoding.EncodeToString(bodyDig.Sum(nil))
	req.Header.Set("Signature", signature)
	return nil
}

func doAuthRequest(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	makeRequest := func(useDecodedKey bool) (*http.Response, error) {
		var reader *bytes.Reader
		if len(body) == 0 {
			reader = bytes.NewReader(nil)
		} else {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, url, reader)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if err := signOrBearerWithKeyMode(req, body, useDecodedKey); err != nil {
			return nil, err
		}
		return client.Do(req)
	}

	resp, err := makeRequest(false)
	if err != nil {
		return nil, err
	}
	if BloodhoundAPITokenID == "" || resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Retry once with base64-decoded key material for environments that store HMAC keys encoded.
	if _, decodeErr := base64.StdEncoding.DecodeString(BloodhoundAPIToken); decodeErr != nil {
		return resp, nil
	}
	if err := resp.Body.Close(); err != nil {
		return nil, err
	}
	return makeRequest(true)
}

func refreshConfigFromRuntime() {
	// Enforce runtime keystore configuration (ignore compile-time values).
	BloodhoundAPIURL = ""
	BloodhoundAPIToken = ""
	BloodhoundAPITokenID = ""

	if v := readFirstRuntime("BLOODHOUND_API_URL", "BLOODHOUND_URL"); v != "" {
		BloodhoundAPIURL = strings.TrimRight(v, "/")
	}
	if v := readFirstRuntime("BLOODHOUND_API_TOKEN", "BLOODHOUND_API_KEY", "BLOODHOUND_TOKEN"); v != "" {
		BloodhoundAPIToken = v
	}
	if v := readFirstRuntime("BLOODHOUND_API_TOKEN_ID", "BLOODHOUND_API_ID", "BLOODHOUND_TOKEN_ID"); v != "" {
		BloodhoundAPITokenID = v
	}
}

// UploadConfigStatus reports if upload is configured and, if not, why.
func UploadConfigStatus() (configured bool, reason string) {
	refreshConfigFromRuntime()

	missing := make([]string, 0, 3)
	if BloodhoundAPIURL == "" {
		missing = append(missing, "BLOODHOUND_API_URL")
	}
	if BloodhoundAPIToken == "" {
		missing = append(missing, "BLOODHOUND_API_TOKEN")
	}
	if len(missing) > 0 {
		return false, "missing " + strings.Join(missing, ", ")
	}
	if _, err := validateBloodhoundAPIURL(BloodhoundAPIURL); err != nil {
		return false, err.Error()
	}

	if looksLikeTokenKey(BloodhoundAPIToken) &&
		!looksLikeJWT(BloodhoundAPIToken) &&
		BloodhoundAPITokenID == "" {
		return false, "missing BLOODHOUND_API_TOKEN_ID (or BLOODHOUND_API_ID) for HMAC token key"
	}

	return true, ""
}

func authMode() string {
	if BloodhoundAPITokenID != "" {
		return "hmac"
	}
	return "bearer"
}

func responseDetail(resp *http.Response) string {
	if resp == nil {
		return "no response"
	}
	location := resp.Header.Get("Location")
	switch {
	case location != "":
		return fmt.Sprintf("status %d (redirect to %s)", resp.StatusCode, location)
	default:
		return fmt.Sprintf("status %d", resp.StatusCode)
	}
}

func readFirstRuntime(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(keystore.RuntimeValue(key)); v != "" {
			return v
		}
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

func looksLikeTokenKey(token string) bool {
	// BloodHound HMAC keys are commonly base64-like strings.
	return strings.ContainsAny(token, "+/=")
}

func validateBloodhoundAPIURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("missing BLOODHOUND_API_URL")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid BLOODHOUND_API_URL: %w", err)
	}
	if strings.TrimSpace(parsed.Host) == "" || strings.TrimSpace(parsed.Scheme) == "" {
		return "", fmt.Errorf("invalid BLOODHOUND_API_URL: missing scheme or host")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		// continue
	case "http":
		if isLocalhost(parsed.Hostname()) {
			// continue
			break
		}
		return "", fmt.Errorf("insecure BLOODHOUND_API_URL %q: use https (http allowed only for localhost)", raw)
	default:
		return "", fmt.Errorf("unsupported BLOODHOUND_API_URL scheme %q", parsed.Scheme)
	}
	parsed.Path = normalizeBloodhoundAPIPath(parsed.Path)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLocalhost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func startUploadJob() (string, error) {
	url := fmt.Sprintf("%s/file-upload/start", BloodhoundAPIURL)
	resp, err := doAuthRequest("POST", url, nil, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"Prefer":       "wait=30",
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 {
		return "", fmt.Errorf("start job %s (api_url=%s auth=%s)", responseDetail(resp), BloodhoundAPIURL, authMode())
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("start job %s (api_url=%s auth=%s): %s", responseDetail(resp), BloodhoundAPIURL, authMode(), string(body))
	}
	var job fileUploadJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return "", err
	}
	if job.Data.ID == 0 {
		return "", fmt.Errorf("missing job id")
	}
	return strconv.Itoa(job.Data.ID), nil
}

func uploadFile(jobID, path, filename string) error {
	data, err := safeio.ReadFile(path)
	if err != nil {
		return err
	}
	uploadName := strings.TrimSpace(filename)
	if uploadName == "" {
		uploadName = filepath.Base(path)
	}

	url := fmt.Sprintf("%s/file-upload/%s", BloodhoundAPIURL, jobID)
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}
	if uploadName != "" {
		headers["X-File-Upload-Name"] = uploadName
	}
	resp, err := doAuthRequest("POST", url, data, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 {
		return fmt.Errorf("upload %s (api_url=%s auth=%s)", responseDetail(resp), BloodhoundAPIURL, authMode())
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload %s (api_url=%s auth=%s): %s", responseDetail(resp), BloodhoundAPIURL, authMode(), string(body))
	}
	return nil
}

func normalizeBloodhoundAPIPath(rawPath string) string {
	clean := path.Clean("/" + strings.TrimSpace(rawPath))
	if clean == "." || clean == "/" {
		return "/api/v2"
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "api") && strings.EqualFold(parts[i+1], "v2") {
			return "/" + strings.Join(parts[:i+2], "/")
		}
	}
	if len(parts) > 0 && strings.EqualFold(parts[len(parts)-1], "api") {
		return "/" + strings.Join(append(parts, "v2"), "/")
	}
	return "/" + strings.Join(append(parts, "api", "v2"), "/")
}

func endUploadJob(jobID string) error {
	url := fmt.Sprintf("%s/file-upload/%s/end", BloodhoundAPIURL, jobID)
	resp, err := doAuthRequest("POST", url, nil, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 {
		return fmt.Errorf("end job %s (api_url=%s auth=%s)", responseDetail(resp), BloodhoundAPIURL, authMode())
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("end job %s (api_url=%s auth=%s): %s", responseDetail(resp), BloodhoundAPIURL, authMode(), string(body))
	}
	return nil
}
