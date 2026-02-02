package bloodhound

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// These values can be set at build time with:
//
//	-ldflags "-X proxywatch/internal/bloodhound.BloodhoundAPIURL=https://<host>/api/v2 -X proxywatch/internal/bloodhound.BloodhoundAPIToken=<token>"
var (
	BloodhoundAPIURL     = ""
	BloodhoundAPIToken   = "" // HMAC token secret or bearer JWT
	BloodhoundAPITokenID = "" // HMAC token id; leave empty to use bearer
	client               = &http.Client{Timeout: 30 * time.Second}
)

func init() {
	if v := os.Getenv("BLOODHOUND_API_URL"); v != "" {
		BloodhoundAPIURL = v
	}
	if v := os.Getenv("BLOODHOUND_API_TOKEN"); v != "" {
		BloodhoundAPIToken = v
	}
	if v := os.Getenv("BLOODHOUND_API_TOKEN_ID"); v != "" {
		BloodhoundAPITokenID = v
	}
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
	if BloodhoundAPIURL == "" || BloodhoundAPIToken == "" {
		return nil // not configured; skip
	}

	tmpFile, err := os.CreateTemp("", "pw-bh-*.json")
	if err != nil {
		return fmt.Errorf("tmpfile: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	if err := WriteJSON(tmpFile.Name(), payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	jobID, err := startUploadJob()
	if err != nil {
		return fmt.Errorf("start upload job: %w", err)
	}

	if err := uploadFile(jobID, tmpFile.Name(), filename); err != nil {
		return fmt.Errorf("upload file: %w", err)
	}

	if err := endUploadJob(jobID); err != nil {
		return fmt.Errorf("end upload job: %w", err)
	}

	return nil
}

func signOrBearer(req *http.Request, body []byte) error {
	if BloodhoundAPITokenID == "" {
		req.Header.Set("Authorization", "Bearer "+BloodhoundAPIToken)
		return nil
	}

	// HMAC signature mode (API key + ID) per BloodHound docs:
	// 1) opKey   = HMAC(key, METHOD+URI)
	// 2) dateKey = HMAC(opKey, RequestDate[:13])  // YYYY-MM-DDTHH
	// 3) sig     = HMAC(dateKey, body)            // body may be empty
	reqDate := time.Now().UTC().Format(time.RFC3339)
	req.Header.Set("RequestDate", reqDate)
	req.Header.Set("Authorization", "bhesignature "+BloodhoundAPITokenID)

	// Use the raw key bytes (docs treat token as the secret itself; base64 decoding can change it)
	keyBytes := []byte(BloodhoundAPIToken)

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

func startUploadJob() (string, error) {
	url := fmt.Sprintf("%s/file-upload/start", BloodhoundAPIURL)
	req, err := http.NewRequest("POST", url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", "wait=30")
	if err := signOrBearer(req, nil); err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("start job status %d: %s", resp.StatusCode, string(body))
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
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/file-upload/%s", BloodhoundAPIURL, jobID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := signOrBearer(req, data); err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func endUploadJob(jobID string) error {
	url := fmt.Sprintf("%s/file-upload/%s/end", BloodhoundAPIURL, jobID)
	req, err := http.NewRequest("POST", url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if err := signOrBearer(req, nil); err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("end job status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
