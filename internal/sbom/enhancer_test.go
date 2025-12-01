package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeSBOMDigest(t *testing.T) {
	tempDir := t.TempDir()
	sbomPath := filepath.Join(tempDir, "sbom.json")

	sbom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]interface{}{
			"timestamp": "2024-01-15T12:00:00Z",
		},
		"components": []interface{}{
			map[string]interface{}{"name": "test", "version": "v1.0.0"},
		},
	}

	data, _ := json.MarshalIndent(sbom, "", "  ")
	os.WriteFile(sbomPath, data, 0644)

	hash, err := ComputeSBOMDigest(sbomPath, "sha256")
	if err != nil {
		t.Fatalf("ComputeSBOMDigest failed: %v", err)
	}

	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}

	hash2, err := ComputeSBOMDigest(sbomPath, "sha256")
	if err != nil {
		t.Fatalf("Second ComputeSBOMDigest failed: %v", err)
	}

	if hash != hash2 {
		t.Errorf("Hash not deterministic: %s != %s", hash, hash2)
	}
}

func TestVerifyReproducible(t *testing.T) {
	tempDir := t.TempDir()

	sbom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]interface{}{
			"timestamp": "2024-01-15T12:00:00Z",
		},
		"components": []interface{}{
			map[string]interface{}{"name": "test", "version": "v1.0.0"},
		},
	}

	sbom1Path := filepath.Join(tempDir, "sbom1.json")
	sbom2Path := filepath.Join(tempDir, "sbom2.json")

	data, _ := json.MarshalIndent(sbom, "", "  ")
	os.WriteFile(sbom1Path, data, 0644)
	os.WriteFile(sbom2Path, data, 0644)

	match, diff, err := VerifyReproducible(sbom1Path, sbom2Path)
	if err != nil {
		t.Fatalf("VerifyReproducible failed: %v", err)
	}

	if !match {
		t.Errorf("SBOMs should match but don't. Diff: %s", diff)
	}

	sbom["components"] = []interface{}{
		map[string]interface{}{"name": "different", "version": "v2.0.0"},
	}
	data, _ = json.MarshalIndent(sbom, "", "  ")
	os.WriteFile(sbom2Path, data, 0644)

	match, diff, err = VerifyReproducible(sbom1Path, sbom2Path)
	if err != nil {
		t.Fatalf("VerifyReproducible failed: %v", err)
	}

	if match {
		t.Error("SBOMs should not match but do")
	}

	if diff == "" {
		t.Error("Expected diff output but got empty string")
	}
}

func TestNormalizeSBOM(t *testing.T) {
	sbom := map[string]interface{}{
		"bomFormat": "CycloneDX",
		"metadata": map[string]interface{}{
			"timestamp": "2024-01-15T12:00:00Z",
			"tool":      "goenv",
		},
		"components": []interface{}{
			map[string]interface{}{"name": "zeta"},
			map[string]interface{}{"name": "alpha"},
		},
	}

	normalized := normalizeSBOM(sbom)

	metadata, ok := normalized["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Normalized metadata not a map")
	}

	if _, hasTimestamp := metadata["timestamp"]; hasTimestamp {
		t.Error("Timestamp should be removed from normalized SBOM")
	}

	if tool, ok := metadata["tool"].(string); !ok || tool != "goenv" {
		t.Error("Other metadata fields should be preserved")
	}

	components, ok := normalized["components"].([]interface{})
	if !ok {
		t.Fatal("Normalized components not an array")
	}

	if len(components) != 2 {
		t.Fatalf("Expected 2 components, got %d", len(components))
	}

	firstComp := components[0].(map[string]interface{})
	firstName, _ := firstComp["name"].(string)
	if firstName != "alpha" {
		t.Errorf("First component should be 'alpha', got '%s'", firstName)
	}
}

func TestGenerateDeterministicUUID(t *testing.T) {
	uuid1 := generateDeterministicUUID("test-content")
	uuid2 := generateDeterministicUUID("test-content")

	if uuid1 != uuid2 {
		t.Errorf("UUIDs should match for same content: %s != %s", uuid1, uuid2)
	}

	uuid3 := generateDeterministicUUID("different-content")
	if uuid1 == uuid3 {
		t.Error("UUIDs should differ for different content")
	}

	if len(uuid1) < 32 {
		t.Errorf("UUID too short: %s", uuid1)
	}
}
