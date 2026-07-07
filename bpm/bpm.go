package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultBPMBuildFile = "Beefile"
const defaultBPMReadmeFile = "README.md"
const defaultBPMBuildEnvironmentFile = "build-environment.json"
const defaultBPMBuildPublicCertificateFile = "cert.der"
const defaultBPMBuildKeysDir = "~/.config/bpm/"

func validateBPMBuildFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("build file is empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read build file %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("build file %s is a directory", path)
	}

	return nil
}

func resolveBPMBuildFilePath(contextDir string, buildFile string, explicitBuildFile bool) (string, error) {
	contextDir = strings.TrimSpace(contextDir)
	if contextDir == "" {
		return "", fmt.Errorf("build context is empty")
	}

	if explicitBuildFile {
		buildFile = strings.TrimSpace(buildFile)
		if buildFile == "" {
			return "", fmt.Errorf("build file is empty")
		}
		return buildFile, nil
	}

	return filepath.Join(contextDir, defaultBPMBuildFile), nil
}

func resolveBPMBuildKeysDir(keysDir string) (string, error) {
	keysDir = strings.TrimSpace(keysDir)
	if keysDir == "" {
		keysDir = defaultBPMBuildKeysDir
	}
	if keysDir == "~" || strings.HasPrefix(keysDir, "~/") {
		home, err := bpmUserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		home = strings.TrimSpace(home)
		if home == "" {
			return "", fmt.Errorf("home directory is empty")
		}
		if keysDir == "~" {
			return home, nil
		}
		keysDir = filepath.Join(home, keysDir[2:])
	}

	return filepath.Clean(keysDir), nil
}
