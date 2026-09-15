package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var bpmPackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type bpmPackageMetadata struct {
	Name        string
	Description string
	License     string
	Authors     []string
}

type bpmBuildSpec struct {
	Metadata  bpmPackageMetadata
	Files     []bpmBuildFileEntry
	Upatches  []bpmBuildUpatchEntry
	ScopeDir  string
	BuildFile []byte
}

type bpmBuildFileEntry struct {
	Source string
	Target string
}

type bpmBuildUpatchEntry struct {
	Source          string
	Type            string
	TelemetryUpatch string
	LoadTarget      string
	UnloadTarget    string
	Tree            *bpmBuildTreeMetadata
}

// bpmBuildTreeMetadata is optional build-time publication metadata.  It is
// kept on each existing [[upatches]] entry so a Beefile can continue to
// describe multiple upatches in declaration order.  The target agent never
// reads this structure: it consumes the signed tree publication instead.
type bpmBuildTreeMetadata struct {
	ID             string
	LoadArtifact   string
	UnloadArtifact string
	Selector       bpmBuildTreeSelector
}

type bpmBuildTreeSelector struct {
	KernelReleasePrefix []string
	Architecture        []string
	Kconfig             map[string][]string
	Labels              map[string][]string
}

func loadBPMBuildMetadata(path string) (bpmPackageMetadata, error) {
	if err := validateBPMBuildFile(path); err != nil {
		return bpmPackageMetadata{}, err
	}

	body, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return bpmPackageMetadata{}, fmt.Errorf("read build file %s: %w", path, err)
	}

	return parseBPMBuildMetadata(body)
}

func loadBPMBuildSpec(buildFilePath string) (bpmBuildSpec, error) {
	if err := validateBPMBuildFile(buildFilePath); err != nil {
		return bpmBuildSpec{}, err
	}

	trimmedPath := strings.TrimSpace(buildFilePath)
	body, err := os.ReadFile(trimmedPath)
	if err != nil {
		return bpmBuildSpec{}, fmt.Errorf("read build file %s: %w", buildFilePath, err)
	}

	spec, err := parseBPMBuildSpec(body)
	if err != nil {
		return bpmBuildSpec{}, err
	}
	spec.BuildFile = append([]byte(nil), body...)
	spec.ScopeDir = filepath.Dir(trimmedPath)

	return spec, nil
}

func parseBPMBuildSpec(body []byte) (bpmBuildSpec, error) {
	metadata, err := parseBPMBuildMetadata(body)
	if err != nil {
		return bpmBuildSpec{}, err
	}

	files, err := parseBPMBuildFiles(body)
	if err != nil {
		return bpmBuildSpec{}, err
	}
	upatches, err := parseBPMBuildUpatches(body)
	if err != nil {
		return bpmBuildSpec{}, err
	}

	return bpmBuildSpec{
		Metadata:  metadata,
		Files:     files,
		Upatches:  upatches,
		BuildFile: append([]byte(nil), body...),
	}, nil
}

func parseBPMBuildMetadata(body []byte) (bpmPackageMetadata, error) {
	manifest, err := parseBPMMetadata(body, false)
	if err != nil {
		return bpmPackageMetadata{}, err
	}

	return bpmPackageMetadata{
		Name:        manifest.Name,
		Description: manifest.Description,
		License:     manifest.License,
		Authors:     manifest.Authors,
	}, nil
}

func parseBPMBuildFiles(body []byte) ([]bpmBuildFileEntry, error) {
	return parseBPMBuildFileEntries(body, bpmBuildFileEntryParseOptions{
		Section:       "files",
		DefaultTarget: func(source string) string { return source },
	})
}

type bpmBuildFileEntryParseOptions struct {
	Section       string
	DefaultTarget func(source string) string
}

func parseBPMBuildFileEntries(body []byte, opts bpmBuildFileEntryParseOptions) ([]bpmBuildFileEntry, error) {
	var entries []bpmBuildFileEntry
	var current *bpmBuildFileEntry
	seenKeys := map[string]struct{}{}
	section := ""

	finishCurrent := func(lineNumber int) error {
		if current == nil {
			return nil
		}
		current.Source = strings.TrimSpace(current.Source)
		current.Target = strings.TrimSpace(current.Target)
		if current.Source == "" {
			return fmt.Errorf("parse %s line %d: %s.source is required", opts.Section, lineNumber, opts.Section)
		}
		if current.Target == "" {
			current.Target = opts.DefaultTarget(current.Source)
		}
		entries = append(entries, *current)
		current = nil
		seenKeys = map[string]struct{}{}
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(stripBPMTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			if err := finishCurrent(lineNumber); err != nil {
				return nil, err
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]"))
			if section == opts.Section {
				current = &bpmBuildFileEntry{}
				seenKeys = map[string]struct{}{}
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if err := finishCurrent(lineNumber); err != nil {
				return nil, err
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			if current != nil {
				if err := finishCurrent(lineNumber); err != nil {
					return nil, err
				}
			}
			continue
		}
		if section != opts.Section || current == nil {
			continue
		}

		key = strings.TrimSpace(key)
		if _, ok := seenKeys[key]; ok {
			return nil, fmt.Errorf("parse %s line %d: duplicate %s field %q", opts.Section, lineNumber, opts.Section, key)
		}
		seenKeys[key] = struct{}{}

		parsed, err := parseBPMTOMLString(value)
		if err != nil {
			return nil, fmt.Errorf("parse %s line %d: %s.%s: %w", opts.Section, lineNumber, opts.Section, key, err)
		}
		switch key {
		case "source":
			current.Source = parsed
		case "target":
			current.Target = parsed
		default:
			return nil, fmt.Errorf("parse %s line %d: unknown %s field %q", opts.Section, lineNumber, opts.Section, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", opts.Section, err)
	}
	if err := finishCurrent(0); err != nil {
		return nil, err
	}

	return entries, nil
}

func parseBPMBuildUpatches(body []byte) ([]bpmBuildUpatchEntry, error) {
	var entries []bpmBuildUpatchEntry
	var current *bpmBuildUpatchEntry
	seenKeys := map[string]struct{}{}
	section := ""

	finishCurrent := func(lineNumber int) error {
		if current == nil {
			return nil
		}
		current.Source = strings.TrimSpace(current.Source)
		current.Type = strings.ToLower(strings.TrimSpace(current.Type))
		current.TelemetryUpatch = strings.TrimSpace(current.TelemetryUpatch)
		current.LoadTarget = strings.TrimSpace(current.LoadTarget)
		current.UnloadTarget = strings.TrimSpace(current.UnloadTarget)
		if current.Source == "" {
			return fmt.Errorf("parse upatches line %d: upatches.source is required", lineNumber)
		}
		if current.Type == "" {
			current.Type = "bpf"
		}
		if current.Type != "bpf" && current.Type != "java" {
			return fmt.Errorf("parse upatches line %d: upatches.type must be bpf or java", lineNumber)
		}
		if current.TelemetryUpatch != "" {
			if current.Type != "java" {
				return fmt.Errorf("parse upatches line %d: upatches.telemetry_upatch requires type java", lineNumber)
			}
			if !bpmPackageNamePattern.MatchString(current.TelemetryUpatch) {
				return fmt.Errorf("parse upatches line %d: upatches.telemetry_upatch is not a valid upatch name", lineNumber)
			}
		}
		if current.LoadTarget == "" {
			current.LoadTarget = defaultBPMBuildUpatchLoadTarget(current.Source)
		}
		if current.UnloadTarget == "" {
			current.UnloadTarget = defaultBPMBuildUpatchUnloadTarget(current.Source)
		}
		if current.Tree != nil {
			current.Tree.ID = strings.TrimSpace(current.Tree.ID)
			current.Tree.LoadArtifact = strings.TrimSpace(current.Tree.LoadArtifact)
			current.Tree.UnloadArtifact = strings.TrimSpace(current.Tree.UnloadArtifact)
			if current.Tree.ID == "" || current.Tree.LoadArtifact == "" ||
				current.Tree.UnloadArtifact == "" {
				return fmt.Errorf("parse upatches line %d: upatches.tree requires id, load_artifact, and unload_artifact", lineNumber)
			}
			if !bpmPackageNamePattern.MatchString(current.Tree.ID) {
				return fmt.Errorf("parse upatches line %d: upatches.tree.id is not a valid upatch id", lineNumber)
			}
			for _, artifact := range []string{current.Tree.LoadArtifact, current.Tree.UnloadArtifact} {
				clean := path.Clean(strings.ReplaceAll(artifact, "\\", "/"))
				if path.IsAbs(artifact) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
					return fmt.Errorf("parse upatches line %d: upatches.tree artifact path %q escapes the package", lineNumber, artifact)
				}
			}
		}
		entries = append(entries, *current)
		current = nil
		seenKeys = map[string]struct{}{}
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(stripBPMTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			if err := finishCurrent(lineNumber); err != nil {
				return nil, err
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]"))
			if section == "upatches" {
				current = &bpmBuildUpatchEntry{}
				seenKeys = map[string]struct{}{}
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			candidate := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if candidate != "upatches.tree" && candidate != "upatches.tree.selector" &&
				candidate != "upatches.tree.selector.kconfig" && candidate != "upatches.tree.selector.labels" {
				if err := finishCurrent(lineNumber); err != nil {
					return nil, err
				}
			}
			if current == nil && strings.HasPrefix(candidate, "upatches.tree") {
				return nil, fmt.Errorf("parse upatches line %d: %s requires a preceding [[upatches]] entry", lineNumber, candidate)
			}
			if strings.HasPrefix(candidate, "upatches.tree") && current.Tree == nil {
				current.Tree = &bpmBuildTreeMetadata{}
			}
			section = candidate
			seenKeys = map[string]struct{}{}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			if current != nil {
				if err := finishCurrent(lineNumber); err != nil {
					return nil, err
				}
			}
			continue
		}
		if current == nil || (section != "upatches" &&
			section != "upatches.tree" && section != "upatches.tree.selector" &&
			section != "upatches.tree.selector.kconfig" &&
			section != "upatches.tree.selector.labels") {
			continue
		}

		key = strings.TrimSpace(key)
		knownTreeKey := false
		if section == "upatches.tree" {
			knownTreeKey = key == "id" || key == "load_artifact" || key == "unload_artifact"
		} else if section == "upatches.tree.selector" {
			knownTreeKey = key == "kernel_release_prefix" || key == "architecture"
		} else if section == "upatches.tree.selector.kconfig" || section == "upatches.tree.selector.labels" {
			knownTreeKey = true
		}
		// Tree metadata is additive. An older/newer publisher may put fields in
		// these tables that this builder does not understand; preserve the
		// existing Beefile compatibility rule and skip those fields.
		if section != "upatches" && !knownTreeKey {
			continue
		}
		if _, ok := seenKeys[key]; ok {
			return nil, fmt.Errorf("parse upatches line %d: duplicate %s field %q", lineNumber, section, key)
		}
		seenKeys[key] = struct{}{}

		if section == "upatches.tree.selector" {
			values, err := parseBPMTOMLStringArray(value)
			if err != nil || len(values) == 0 {
				if err == nil {
					err = fmt.Errorf("must contain at least one string")
				}
				return nil, fmt.Errorf("parse upatches line %d: upatches.%s: %w", lineNumber, key, err)
			}
			if key == "kernel_release_prefix" {
				current.Tree.Selector.KernelReleasePrefix = values
			} else {
				current.Tree.Selector.Architecture = values
			}
			continue
		}
		if section == "upatches.tree.selector.kconfig" || section == "upatches.tree.selector.labels" {
			values, err := parseBPMTOMLStringArray(value)
			if err != nil || len(values) == 0 {
				if err == nil {
					err = fmt.Errorf("must contain at least one string")
				}
				return nil, fmt.Errorf("parse upatches line %d: upatches.%s.%s: %w", lineNumber, section, key, err)
			}
			if section == "upatches.tree.selector.kconfig" {
				if current.Tree.Selector.Kconfig == nil {
					current.Tree.Selector.Kconfig = map[string][]string{}
				}
				current.Tree.Selector.Kconfig[key] = values
			} else {
				if current.Tree.Selector.Labels == nil {
					current.Tree.Selector.Labels = map[string][]string{}
				}
				current.Tree.Selector.Labels[key] = values
			}
			continue
		}
		parsed, err := parseBPMTOMLString(value)
		if err != nil {
			return nil, fmt.Errorf("parse upatches line %d: upatches.%s: %w", lineNumber, key, err)
		}
		if section == "upatches" {
			switch key {
			case "source":
				current.Source = parsed
			case "type":
				current.Type = parsed
			case "telemetry_upatch":
				current.TelemetryUpatch = parsed
			case "load_target":
				current.LoadTarget = parsed
			case "unload_target":
				current.UnloadTarget = parsed
			default:
				return nil, fmt.Errorf("parse upatches line %d: unknown upatches field %q", lineNumber, key)
			}
			continue
		}
		if current.Tree == nil {
			return nil, fmt.Errorf("parse upatches line %d: tree metadata is not initialized", lineNumber)
		}
		switch section {
		case "upatches.tree":
			switch key {
			case "id":
				current.Tree.ID = parsed
			case "load_artifact":
				current.Tree.LoadArtifact = parsed
			case "unload_artifact":
				current.Tree.UnloadArtifact = parsed
				// Unknown tree metadata is ignored for forward compatibility.
			}
		case "upatches.tree.selector":
			// Selector arrays are parsed and assigned above.
		case "upatches.tree.selector.kconfig", "upatches.tree.selector.labels":
			// Selector arrays are parsed and assigned above.
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse upatches: %w", err)
	}
	if err := finishCurrent(0); err != nil {
		return nil, err
	}

	return entries, nil
}

func defaultBPMBuildUpatchLoadTarget(source string) string {
	name := bpmBuildUpatchName(source)
	if name == "" {
		return ""
	}
	return path.Join("upatches", name+".upatch")
}

func defaultBPMBuildUpatchUnloadTarget(source string) string {
	name := bpmBuildUpatchName(source)
	if name == "" {
		return ""
	}
	return path.Join("upatches", name+".unload.upatch")
}

func bpmBuildUpatchName(source string) string {
	source = strings.ReplaceAll(strings.TrimSpace(source), "\\", "/")
	base := path.Base(source)
	if base == "." || base == "/" {
		return ""
	}
	if strings.HasSuffix(base, ".bpf.c") {
		return strings.TrimSuffix(base, ".bpf.c")
	}
	ext := path.Ext(base)
	if ext != "" {
		return strings.TrimSuffix(base, ext)
	}
	return base
}

func bpmBuildUpatchType(upatch bpmBuildUpatchEntry) string {
	typ := strings.ToLower(strings.TrimSpace(upatch.Type))
	if typ != "" {
		return typ
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(upatch.Source)), ".jar") {
		return "java"
	}
	return "bpf"
}

func parseBPMMetadata(body []byte, allowVersion bool) (bpmPackageManifest, error) {
	var metadata bpmPackageManifest
	seenPackage := false
	seenKeys := map[string]struct{}{}
	section := ""

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(stripBPMTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if section == "package" {
				seenPackage = true
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			if seenPackage {
				break
			}
			continue
		}
		if section != "package" {
			continue
		}

		key = strings.TrimSpace(key)
		if _, ok := seenKeys[key]; ok {
			return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: duplicate package field %q", lineNumber, key)
		}
		seenKeys[key] = struct{}{}

		switch key {
		case "name":
			name, err := parseBPMTOMLString(value)
			if err != nil {
				return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: package.name: %w", lineNumber, err)
			}
			metadata.Name = strings.TrimSpace(name)
		case "version":
			if !allowVersion {
				return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: unknown package field %q", lineNumber, key)
			}
			version, err := parseBPMTOMLString(value)
			if err != nil {
				return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: package.version: %w", lineNumber, err)
			}
			metadata.Version = strings.TrimSpace(version)
		case "description":
			description, err := parseBPMTOMLString(value)
			if err != nil {
				return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: package.description: %w", lineNumber, err)
			}
			metadata.Description = description
		case "license":
			license, err := parseBPMTOMLString(value)
			if err != nil {
				return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: package.license: %w", lineNumber, err)
			}
			metadata.License = strings.TrimSpace(license)
		case "authors":
			authors, err := parseBPMTOMLStringArray(value)
			if err != nil {
				return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: package.authors: %w", lineNumber, err)
			}
			metadata.Authors = authors
		default:
			return bpmPackageManifest{}, fmt.Errorf("parse metadata line %d: unknown package field %q", lineNumber, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return bpmPackageManifest{}, fmt.Errorf("parse metadata: %w", err)
	}

	if !seenPackage {
		return bpmPackageManifest{}, fmt.Errorf("metadata missing [package] table")
	}
	if metadata.Name == "" {
		return bpmPackageManifest{}, fmt.Errorf("metadata package.name is required")
	}
	if !bpmPackageNamePattern.MatchString(metadata.Name) {
		return bpmPackageManifest{}, fmt.Errorf("metadata package.name %q must contain only letters, numbers, dots, underscores, and hyphens", metadata.Name)
	}

	return metadata, nil
}

func resolveBPMBuildFiles(scopeDir string, entries []bpmBuildFileEntry) ([]bpmPackageFile, error) {
	return resolveBPMBuildFileGroups(scopeDir, []bpmBuildFileGroup{{
		Section: "files",
		Entries: entries,
	}})
}

func resolveBPMBuildPackageFiles(scopeDir string, files []bpmBuildFileEntry, upatches []bpmBuildUpatchEntry) ([]bpmPackageFile, error) {
	loads, unloads, err := bpmBuildUpatchFileEntries(upatches)
	if err != nil {
		return nil, err
	}
	return resolveBPMBuildFileGroups(scopeDir, []bpmBuildFileGroup{
		{
			Section: "files",
			Entries: files,
		},
		{
			Section: "upatches.load",
			Entries: loads,
			Upatch:  true,
		},
		{
			Section: "upatches.unload",
			Entries: unloads,
			Upatch:  true,
		},
	})
}

func validateBPMBuildPackageTargets(files []bpmBuildFileEntry, upatches []bpmBuildUpatchEntry) error {
	loads, unloads, err := bpmBuildUpatchFileEntries(upatches)
	if err != nil {
		return err
	}
	return validateBPMBuildFileGroupTargets([]bpmBuildFileGroup{
		{
			Section: "files",
			Entries: files,
		},
		{
			Section: "upatches.load",
			Entries: loads,
		},
		{
			Section: "upatches.unload",
			Entries: unloads,
		},
	})
}

func bpmBuildUpatchFileEntries(upatches []bpmBuildUpatchEntry) ([]bpmBuildFileEntry, []bpmBuildFileEntry, error) {
	loads := make([]bpmBuildFileEntry, 0, len(upatches))
	unloads := make([]bpmBuildFileEntry, 0, len(upatches))
	for _, upatch := range upatches {
		load, err := bpmBuildUpatchFileEntry(upatch.LoadTarget, "upatches.load_target")
		if err != nil {
			return nil, nil, err
		}
		unload, err := bpmBuildUpatchFileEntry(upatch.UnloadTarget, "upatches.unload_target")
		if err != nil {
			return nil, nil, err
		}
		loads = append(loads, bpmBuildFileEntry{
			Source: load.Source,
			Target: load.Target,
		})
		unloads = append(unloads, bpmBuildFileEntry{
			Source: unload.Source,
			Target: unload.Target,
		})
	}
	return loads, unloads, nil
}

func bpmBuildUpatchFileEntry(target string, field string) (bpmBuildFileEntry, error) {
	cleanTarget, err := normalizeBPMArchivePath(target, field)
	if err != nil {
		return bpmBuildFileEntry{}, err
	}
	source := path.Base(cleanTarget)
	if source == "." || source == "/" || source == "" {
		return bpmBuildFileEntry{}, fmt.Errorf("%s %q does not name an upatch output file", field, target)
	}
	return bpmBuildFileEntry{
		Source: source,
		Target: cleanTarget,
	}, nil
}

type bpmBuildFileGroup struct {
	Section string
	Entries []bpmBuildFileEntry
	Upatch  bool
}

func resolveBPMBuildFileGroups(scopeDir string, groups []bpmBuildFileGroup) ([]bpmPackageFile, error) {
	scopePath, err := resolveBPMBuildScopePath(scopeDir)
	if err != nil {
		return nil, err
	}

	if err := validateBPMBuildFileGroupTargets(groups); err != nil {
		return nil, err
	}
	fileCount := 0
	for _, group := range groups {
		fileCount += len(group.Entries)
	}
	files := make([]bpmPackageFile, 0, fileCount)
	for _, group := range groups {
		for _, entry := range group.Entries {
			target, err := normalizeBPMBuildFileTarget(entry.Target, group.Section)
			if err != nil {
				return nil, err
			}

			sourcePath, info, err := resolveBPMBuildFileSource(scopePath, entry.Source, group.Section)
			if err != nil {
				return nil, err
			}
			body, err := os.ReadFile(sourcePath)
			if err != nil {
				return nil, fmt.Errorf("read package source %s: %w", entry.Source, err)
			}

			mode := int64(info.Mode().Perm())
			if mode == 0 {
				mode = 0o644
			}
			files = append(files, bpmPackageFile{
				Target: target,
				Body:   body,
				Mode:   mode,
				Upatch: group.Upatch,
			})
		}
	}

	return files, nil
}

func resolveBPMBuildScopePath(scopeDir string) (string, error) {
	scopeDir = strings.TrimSpace(scopeDir)
	if scopeDir == "" {
		scopeDir = "."
	}
	scopePath, err := filepath.Abs(scopeDir)
	if err != nil {
		return "", fmt.Errorf("resolve build scope: %w", err)
	}
	scopePath, err = filepath.EvalSymlinks(scopePath)
	if err != nil {
		return "", fmt.Errorf("resolve build scope %s: %w", scopeDir, err)
	}

	return scopePath, nil
}

func validateBPMBuildFileGroupTargets(groups []bpmBuildFileGroup) error {
	seenTargets := map[string]struct{}{
		defaultBPMBuildFile:                  {},
		defaultBPMReadmeFile:                 {},
		defaultBPMBuildEnvironmentFile:       {},
		defaultBPMBuildPublicCertificateFile: {},
	}
	for _, group := range groups {
		for _, entry := range group.Entries {
			target, err := normalizeBPMBuildFileTarget(entry.Target, group.Section)
			if err != nil {
				return err
			}
			if _, ok := seenTargets[target]; ok {
				return fmt.Errorf("package target %q is duplicated or reserved", target)
			}
			seenTargets[target] = struct{}{}
		}
	}

	return nil
}

func resolveBPMBuildFileSource(scopePath string, source string, section string) (string, os.FileInfo, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", nil, fmt.Errorf("%s.source is empty", section)
	}
	if filepath.IsAbs(source) {
		return "", nil, fmt.Errorf("%s.source %q must be relative to the Beefile directory", section, source)
	}
	cleanSource := filepath.Clean(source)
	if cleanSource == "." || cleanSource == ".." || strings.HasPrefix(cleanSource, ".."+string(filepath.Separator)) {
		return "", nil, fmt.Errorf("%s.source %q escapes the Beefile directory", section, source)
	}

	sourcePath := filepath.Join(scopePath, cleanSource)
	info, err := os.Stat(sourcePath)
	if err != nil {
		return "", nil, fmt.Errorf("stat package source %s: %w", source, err)
	}
	if info.IsDir() {
		return "", nil, fmt.Errorf("%s.source %q is a directory", section, source)
	}

	resolvedSource, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		return "", nil, fmt.Errorf("resolve package source %s: %w", source, err)
	}
	if !pathWithinDir(scopePath, resolvedSource) {
		return "", nil, fmt.Errorf("%s.source %q escapes the Beefile directory", section, source)
	}

	return resolvedSource, info, nil
}

func normalizeBPMBuildFileTarget(target string, section string) (string, error) {
	return normalizeBPMArchivePath(target, section+".target")
}

func normalizeBPMArchivePath(target string, field string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("%s is empty", field)
	}
	target = strings.ReplaceAll(target, "\\", "/")
	if path.IsAbs(target) {
		return "", fmt.Errorf("%s %q must be relative", field, target)
	}
	cleanTarget := path.Clean(target)
	if cleanTarget == "." || cleanTarget == ".." || strings.HasPrefix(cleanTarget, "../") {
		return "", fmt.Errorf("%s %q escapes the package directory", field, target)
	}

	return cleanTarget, nil
}

func pathWithinDir(dir string, candidate string) bool {
	rel, err := filepath.Rel(dir, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func stripBPMTOMLComment(line string) string {
	inBasicString := false
	inLiteralString := false
	escaped := false

	for i, r := range line {
		switch {
		case escaped:
			escaped = false
		case inBasicString && r == '\\':
			escaped = true
		case !inLiteralString && r == '"':
			inBasicString = !inBasicString
		case !inBasicString && r == '\'':
			inLiteralString = !inLiteralString
		case !inBasicString && !inLiteralString && r == '#':
			return line[:i]
		}
	}

	return line
}

func parseBPMTOMLString(value string) (string, error) {
	parsed, rest, err := parseBPMTOMLStringToken(value)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(rest) != "" {
		return "", fmt.Errorf("unexpected trailing value %q", strings.TrimSpace(rest))
	}

	return parsed, nil
}

func parseBPMTOMLStringArray(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("must be a string array")
	}

	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	if inner == "" {
		return nil, nil
	}

	var values []string
	for inner != "" {
		parsed, rest, err := parseBPMTOMLStringToken(inner)
		if err != nil {
			return nil, err
		}
		values = append(values, parsed)

		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		if !strings.HasPrefix(rest, ",") {
			return nil, fmt.Errorf("expected comma after string array value")
		}
		inner = strings.TrimSpace(strings.TrimPrefix(rest, ","))
		if inner == "" {
			return nil, fmt.Errorf("trailing comma is not supported")
		}
	}

	return values, nil
}

func parseBPMTOMLStringToken(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("must be a string")
	}

	switch value[0] {
	case '"':
		escaped := false
		for i := 1; i < len(value); i++ {
			switch {
			case escaped:
				escaped = false
			case value[i] == '\\':
				escaped = true
			case value[i] == '"':
				parsed, err := strconv.Unquote(value[:i+1])
				if err != nil {
					return "", "", err
				}
				return parsed, value[i+1:], nil
			}
		}
	case '\'':
		for i := 1; i < len(value); i++ {
			if value[i] == '\'' {
				return value[1:i], value[i+1:], nil
			}
		}
	}

	return "", "", fmt.Errorf("must be a string")
}
