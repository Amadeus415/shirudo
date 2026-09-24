package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBPMTreePublicationOmitsGlobalTreeRootFields(t *testing.T) {
	op := bpmTreeOperation{
		Seq: 1,
		Op:  "add",
		ID:  "example",
		Artifact: bpmTreeArtifact{
			Repository:     "oci://registry.example/tree",
			ManifestDigest: "sha256:" + strings.Repeat("a", 64),
			LayerDigest:    "sha256:" + strings.Repeat("b", 64),
			PayloadSHA256:  "sha256:" + strings.Repeat("c", 64),
		},
		OperationDigest: "sha256:" + strings.Repeat("d", 64),
	}
	publication := bpmTreePublication{
		Schema:     2,
		TreeID:     "stable",
		Generation: 1,
		Base:       bpmTreeBase{Seq: 0},
		Operations: []bpmTreeOperation{op},
		Head:       bpmTreeHead{Seq: 1},
	}

	body, err := json.Marshal(publication)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	text := string(body)
	for _, field := range []string{"leaf_hash", "mmr_root", "tree_root"} {
		if strings.Contains(text, field) {
			t.Fatalf("publication contains removed field %q: %s", field, text)
		}
	}
	if !strings.Contains(text, `"base":{"seq":0}`) ||
		!strings.Contains(text, `"head":{"seq":1}`) {
		t.Fatalf("publication lost sequence bounds: %s", text)
	}
}

func TestBPMTreeOperationDigestIsStable(t *testing.T) {
	op := bpmTreeOperation{
		Seq: 7,
		Op:  "delete",
		ID:  "example",
		Selector: bpmTreeSelector{
			KernelReleasePrefix: []string{"6.18"},
			KernelBuildID:       []string{"deadbeef"},
		},
		Artifact: bpmTreeArtifact{
			Repository:     "oci://registry.example/tree",
			ManifestDigest: "sha256:" + strings.Repeat("a", 64),
			LayerDigest:    "sha256:" + strings.Repeat("b", 64),
			PayloadSHA256:  "sha256:" + strings.Repeat("c", 64),
		},
	}

	first, err := bpmTreeOperationDigest(op)
	if err != nil {
		t.Fatalf("first digest error = %v", err)
	}
	second, err := bpmTreeOperationDigest(op)
	if err != nil {
		t.Fatalf("second digest error = %v", err)
	}
	if first != second || !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("operation digest = %q, repeated digest = %q", first, second)
	}
}
