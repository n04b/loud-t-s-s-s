package loudtsss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	blockPrefix = "enc:v1:"
	keyPrefix   = "loudtsss-key:v1:"
	keyEnvVar   = "LOUD_T_S_S_S_KEY_"
	keysDirVar  = "LOUD_T_S_S_S_KEYS_DIR"
)

// Key IDs become file names, so they never contain dots or slashes.
var reKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

// Key is a 256-bit AES key of one environment.
type Key struct {
	ID    string
	Bytes []byte
}

// String is the key's text form, stored in key files and environment variables: "loudtsss-key:v1:<keyId>:<base64>".
func (k Key) String() string {
	return keyPrefix + k.ID + ":" + base64.StdEncoding.EncodeToString(k.Bytes)
}

func generateKey(env string) (Key, error) {
	b := make([]byte, 32)
	suffix := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return Key{}, err
	}
	if _, err := rand.Read(suffix); err != nil {
		return Key{}, err
	}
	return Key{ID: env + "-" + hex.EncodeToString(suffix), Bytes: b}, nil
}

func parseKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, keyPrefix) {
		return Key{}, errors.New(`not a loudTSSS key (expected "loudtsss-key:v1:<keyId>:<base64>")`)
	}
	id, b64, ok := strings.Cut(strings.TrimPrefix(s, keyPrefix), ":")
	if !ok || !reKeyID.MatchString(id) {
		return Key{}, errors.New("malformed key id")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return Key{}, errors.New("key material must be 32 bytes in base64")
	}
	return Key{ID: id, Bytes: b}, nil
}

// aad binds a block to its environment: a block moved to another environment fails authentication.
func aad(env string) []byte {
	b, _ := marshal([]string{FormatID, env})
	return b
}

func gcm(k Key) (cipher.AEAD, error) {
	c, err := aes.NewCipher(k.Bytes)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// seal encrypts a payload into "enc:v1:<keyId>:<base64(nonce || ciphertext || tag)>".
func seal(env string, k Key, p *Payload) (string, error) {
	pt, err := marshal(p)
	if err != nil {
		return "", err
	}
	g, err := gcm(k)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := g.Seal(nonce, nonce, pt, aad(env))
	return blockPrefix + k.ID + ":" + base64.StdEncoding.EncodeToString(out), nil
}

// blockKeyID reads the key id from a block's header without decrypting it.
func blockKeyID(s string) (string, []byte, error) {
	if !strings.HasPrefix(s, blockPrefix) {
		return "", nil, errors.New(`malformed block: expected "enc:v1:<keyId>:<base64>"`)
	}
	id, b64, ok := strings.Cut(strings.TrimPrefix(s, blockPrefix), ":")
	if !ok || !reKeyID.MatchString(id) {
		return "", nil, errors.New("malformed block: bad key id")
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", nil, errors.New("malformed block: not valid base64")
	}
	return id, data, nil
}

func open(env string, k Key, s string) (*Payload, error) {
	_, data, err := blockKeyID(s)
	if err != nil {
		return nil, err
	}
	g, err := gcm(k)
	if err != nil {
		return nil, err
	}
	if len(data) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("malformed block: too short")
	}
	pt, err := g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], aad(env))
	if err != nil {
		return nil, errors.New("AES-GCM authentication failed: the block was modified, belongs to another environment, or the key is wrong")
	}
	var p Payload
	if err := decodeStrict(pt, &p); err != nil {
		return nil, fmt.Errorf("decrypted block is not valid: %v", err)
	}
	return &p, nil
}

// KeyStore finds keys in an environment variable or in a directory outside the repository.
type KeyStore struct {
	Dir    string
	Getenv func(string) string
}

func envVarFor(env string) string {
	return keyEnvVar + strings.ToUpper(strings.ReplaceAll(env, "-", "_"))
}

// Find returns the key with keyID for env. ok is false when the key is simply not on this machine.
func (ks KeyStore) Find(env, keyID string) (k Key, ok bool, err error) {
	if v := ks.Getenv(envVarFor(env)); v != "" {
		k, err := parseKey(v)
		if err != nil {
			return Key{}, false, fmt.Errorf("%s: %v", envVarFor(env), err)
		}
		if k.ID != keyID {
			return Key{}, false, fmt.Errorf("%s holds key %s, but the %s block is encrypted with %s", envVarFor(env), k.ID, env, keyID)
		}
		return k, true, nil
	}
	if ks.Dir == "" {
		return Key{}, false, nil
	}
	path := filepath.Join(ks.Dir, keyID+".key")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Key{}, false, nil
	}
	if err != nil {
		return Key{}, false, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Key{}, false, fmt.Errorf("%s is readable by other users (mode %v); run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Key{}, false, err
	}
	k, err = parseKey(string(b))
	if err != nil {
		return Key{}, false, fmt.Errorf("%s: %v", path, err)
	}
	if k.ID != keyID {
		return Key{}, false, fmt.Errorf("%s holds key %s, expected %s", path, k.ID, keyID)
	}
	return k, true, nil
}

// Save writes a new key file with mode 0600; it never overwrites an existing one.
func (ks KeyStore) Save(k Key) (string, error) {
	if ks.Dir == "" {
		return "", errors.New("no keys directory: pass --keys-dir or set " + keysDirVar)
	}
	if err := os.MkdirAll(ks.Dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(ks.Dir, k.ID+".key")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(k.String() + "\n"); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close()
}
