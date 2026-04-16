package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveKeyFromHMAC_Deterministic(t *testing.T) {
	// Same input → same derived key (SHA256 is deterministic).
	key1 := deriveKeyFromHMAC("abcdef0123456789")
	key2 := deriveKeyFromHMAC("abcdef0123456789")
	if string(key1) != string(key2) {
		t.Errorf("same input should produce same key")
	}
	// Different input → different key.
	key3 := deriveKeyFromHMAC("fedcba9876543210")
	if string(key1) == string(key3) {
		t.Errorf("different inputs must produce different keys")
	}
	// Output is 32 bytes (AES-256 key size).
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

func TestSaveLoadNonSecure_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")

	values := map[string]string{
		"OPENAI_API_KEY":    "sk-abc123",
		"ANTHROPIC_API_KEY": "sk-ant-456",
	}
	if err := SaveNonSecure(path, values); err != nil {
		t.Fatalf("SaveNonSecure: %v", err)
	}

	loaded, err := LoadNonSecure(path)
	if err != nil {
		t.Fatalf("LoadNonSecure: %v", err)
	}
	for k, want := range values {
		if got := loaded[k]; got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
}

func TestSavePasswordLoadPassword_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw-keystore.enc")

	values := map[string]string{
		"OPENAI_API_KEY": "sk-very-secret-value",
	}
	pw := "correct horse battery staple"
	if err := SavePassword(path, pw, values); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}

	loaded, err := LoadPassword(path, pw)
	if err != nil {
		t.Fatalf("LoadPassword: %v", err)
	}
	if loaded["OPENAI_API_KEY"] != "sk-very-secret-value" {
		t.Errorf("decryption mismatch: %q", loaded["OPENAI_API_KEY"])
	}
}

func TestLoadPassword_WrongPasswordFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw-keystore.enc")

	if err := SavePassword(path, "right-password", map[string]string{"OPENAI_API_KEY": "y"}); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}

	if _, err := LoadPassword(path, "wrong-password"); err == nil {
		t.Errorf("wrong password should fail decryption")
	}
}

func TestSavePassword_EmptyPasswordRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw-keystore.enc")

	if err := SavePassword(path, "", map[string]string{"OPENAI_API_KEY": "y"}); err == nil {
		t.Errorf("empty password should be rejected")
	}
}

func TestIsPasswordKeystore_DetectsFormat(t *testing.T) {
	dir := t.TempDir()
	pwPath := filepath.Join(dir, "pw.enc")
	plainPath := filepath.Join(dir, "plain.json")

	_ = SavePassword(pwPath, "x", map[string]string{"OPENAI_API_KEY": "B"})
	_ = SaveNonSecure(plainPath, map[string]string{"OPENAI_API_KEY": "B"})

	if !IsPasswordKeystore(pwPath) {
		t.Errorf("password-encrypted keystore not detected")
	}
	if IsPasswordKeystore(plainPath) {
		t.Errorf("plain keystore mis-detected as password-encrypted")
	}
	// Non-existent path → false (not an error).
	if IsPasswordKeystore(filepath.Join(dir, "does-not-exist.json")) {
		t.Errorf("non-existent path should return false")
	}
}

func TestSavePassword_CiphertextDiffersFromPlaintext(t *testing.T) {
	// Sanity: saved file must not contain the plaintext value.
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.enc")
	plaintext := "CANARY-STRING-MUST-NOT-APPEAR-IN-CIPHERTEXT"
	if err := SavePassword(path, "pw", map[string]string{"OPENAI_API_KEY": plaintext}); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	data, err := readTestFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if containsSub(data, []byte(plaintext)) {
		t.Errorf("ciphertext leaked plaintext")
	}
}

// helpers avoid extra imports in the test file.
func readTestFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func containsSub(hay, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
