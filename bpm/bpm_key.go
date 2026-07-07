package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const defaultBPMShirudoKeysDir = "/var/lib/shirudo/keys"

type bpmKeyAddResult struct {
	Fingerprint string
	KeyPath     string
	ActivePath  string
	Active      bool
}

type bpmActiveKeyState struct {
	Create bool
	Active bool
}

func listBPMKeys(keysDir string) ([]string, error) {
	root, ok, err := resolveBPMKeyDir(keysDir)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read Shirudo keys directory %s: %w", root, err)
	}

	fingerprints := make([]string, 0, len(entries))
	for _, entry := range entries {
		filenameFingerprint, ok := bpmKeyFingerprintFromFilename(entry.Name())
		if !ok {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat Shirudo public certificate %s: %w", filepath.Join(root, entry.Name()), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}

		body, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read Shirudo public certificate %s: %w", filepath.Join(root, entry.Name()), err)
		}
		fingerprint, err := bpmSPKISHA256Fingerprint(body)
		if err != nil || !strings.EqualFold(fingerprint, filenameFingerprint) {
			continue
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)

	return fingerprints, nil
}

func addBPMKey(ctx context.Context, source string, keysDir string, httpClient *http.Client) (bpmKeyAddResult, error) {
	certificate, err := bpmPackagePublicCertificateFromSource(ctx, source, httpClient)
	if err != nil {
		return bpmKeyAddResult{}, err
	}
	fingerprint, err := bpmSPKISHA256Fingerprint(certificate)
	if err != nil {
		return bpmKeyAddResult{}, fmt.Errorf("fingerprint packaged Shirudo SPKI: %w", err)
	}

	root, err := prepareBPMKeyDir(keysDir)
	if err != nil {
		return bpmKeyAddResult{}, err
	}

	keyPath := filepath.Join(root, fingerprint+".der")
	activePath := filepath.Join(root, defaultBPMBuildPublicCertificateFile)
	active, err := inspectBPMActiveKey(root, activePath, keyPath, certificate)
	if err != nil {
		return bpmKeyAddResult{}, err
	}

	if err := writeBPMKeyFile(root, keyPath, certificate); err != nil {
		return bpmKeyAddResult{}, err
	}
	if active.Create {
		if err := os.Symlink(filepath.Base(keyPath), activePath); err != nil {
			if !os.IsExist(err) {
				return bpmKeyAddResult{}, fmt.Errorf("activate Shirudo public certificate %s: %w", activePath, err)
			}
			active, err = inspectBPMActiveKey(root, activePath, keyPath, certificate)
			if err != nil {
				return bpmKeyAddResult{}, err
			}
		}
	}

	return bpmKeyAddResult{
		Fingerprint: fingerprint,
		KeyPath:     keyPath,
		ActivePath:  activePath,
		Active:      active.Active,
	}, nil
}

func prepareBPMKeyDir(keysDir string) (string, error) {
	root, err := bpmKeyDirPath(keysDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("create Shirudo keys directory %s: %w", root, err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve Shirudo keys directory %s: %w", keysDir, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("stat Shirudo keys directory %s: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("Shirudo keys path %s is not a directory", root)
	}

	return root, nil
}

func resolveBPMKeyDir(keysDir string) (string, bool, error) {
	root, err := bpmKeyDirPath(keysDir)
	if err != nil {
		return "", false, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("resolve Shirudo keys directory %s: %w", root, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("stat Shirudo keys directory %s: %w", root, err)
	}
	if !info.IsDir() {
		return "", false, fmt.Errorf("Shirudo keys path %s is not a directory", root)
	}

	return root, true, nil
}

func bpmKeyDirPath(keysDir string) (string, error) {
	keysDir = strings.TrimSpace(keysDir)
	if keysDir == "" {
		keysDir = defaultBPMShirudoKeysDir
	}

	root, err := filepath.Abs(keysDir)
	if err != nil {
		return "", fmt.Errorf("resolve Shirudo keys directory %s: %w", keysDir, err)
	}

	return root, nil
}

func bpmKeyFingerprintFromFilename(name string) (string, bool) {
	const suffix = ".der"
	name = strings.TrimSpace(name)
	if !strings.HasSuffix(strings.ToLower(name), suffix) {
		return "", false
	}
	fingerprint := name[:len(name)-len(suffix)]
	if len(fingerprint) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return "", false
	}

	return strings.ToLower(fingerprint), true
}

func inspectBPMActiveKey(root string, activePath string, keyPath string, certificate []byte) (bpmActiveKeyState, error) {
	if !pathWithinDir(root, activePath) {
		return bpmActiveKeyState{}, fmt.Errorf("active Shirudo public certificate path %s escapes keys directory %s", activePath, root)
	}

	info, err := os.Lstat(activePath)
	if os.IsNotExist(err) {
		return bpmActiveKeyState{Create: true, Active: true}, nil
	}
	if err != nil {
		return bpmActiveKeyState{}, fmt.Errorf("stat active Shirudo public certificate %s: %w", activePath, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(activePath)
		if err != nil {
			return bpmActiveKeyState{}, fmt.Errorf("read active Shirudo public certificate link %s: %w", activePath, err)
		}
		resolved, err := resolveBPMKeyLink(root, activePath, link)
		if err != nil {
			return bpmActiveKeyState{}, err
		}
		if filepath.Clean(resolved) == filepath.Clean(keyPath) {
			return bpmActiveKeyState{Active: true}, nil
		}
		body, err := os.ReadFile(resolved)
		if err == nil && bytes.Equal(body, certificate) {
			return bpmActiveKeyState{Active: true}, nil
		}
		return bpmActiveKeyState{}, fmt.Errorf("active Shirudo public certificate %s already points to %s; refusing to replace it", activePath, link)
	}
	if info.IsDir() {
		return bpmActiveKeyState{}, fmt.Errorf("active Shirudo public certificate %s is a directory", activePath)
	}

	body, err := os.ReadFile(activePath)
	if err != nil {
		return bpmActiveKeyState{}, fmt.Errorf("read active Shirudo public certificate %s: %w", activePath, err)
	}
	if !bytes.Equal(body, certificate) {
		return bpmActiveKeyState{}, fmt.Errorf("active Shirudo public certificate %s already exists and differs; refusing to replace it", activePath)
	}

	return bpmActiveKeyState{Active: true}, nil
}

func resolveBPMKeyLink(root string, activePath string, link string) (string, error) {
	resolved := link
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(activePath), resolved)
	}
	resolved = filepath.Clean(resolved)
	if !pathWithinDir(root, resolved) {
		return "", fmt.Errorf("active Shirudo public certificate link %s points outside keys directory %s", link, root)
	}

	return resolved, nil
}

func writeBPMKeyFile(root string, keyPath string, certificate []byte) error {
	if !pathWithinDir(root, keyPath) {
		return fmt.Errorf("Shirudo public certificate path %s escapes keys directory %s", keyPath, root)
	}

	info, err := os.Lstat(keyPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Shirudo public certificate path %s is a symlink", keyPath)
		}
		if info.IsDir() {
			return fmt.Errorf("Shirudo public certificate path %s is a directory", keyPath)
		}
		body, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("read Shirudo public certificate %s: %w", keyPath, err)
		}
		if !bytes.Equal(body, certificate) {
			return fmt.Errorf("Shirudo public certificate %s already exists and differs", keyPath)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat Shirudo public certificate %s: %w", keyPath, err)
	}

	out, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("write Shirudo public certificate %s: %w", keyPath, err)
	}
	if _, err := out.Write(certificate); err != nil {
		out.Close()
		return fmt.Errorf("write Shirudo public certificate %s: %w", keyPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close Shirudo public certificate %s: %w", keyPath, err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		return fmt.Errorf("chmod Shirudo public certificate %s: %w", keyPath, err)
	}

	return nil
}
