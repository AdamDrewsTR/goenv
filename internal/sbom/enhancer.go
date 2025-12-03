package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-nv/goenv/internal/config"
	"github.com/go-nv/goenv/internal/manager"
	"github.com/go-nv/goenv/internal/platform"
	"github.com/go-nv/goenv/internal/utils"
)

// Enhancer adds Go-aware metadata to CycloneDX SBOMs
type Enhancer struct {
	config  *config.Config
	manager *manager.Manager
}

// NewEnhancer creates a new SBOM enhancer
func NewEnhancer(cfg *config.Config, mgr *manager.Manager) *Enhancer {
	return &Enhancer{
		config:  cfg,
		manager: mgr,
	}
}

// EnhanceOptions configures SBOM enhancement behavior
type EnhanceOptions struct {
	ProjectDir    string
	Deterministic bool
	OfflineMode   bool
	EmbedDigests  bool
}

// GoenvMetadata contains Go-specific build and module context
type GoenvMetadata struct {
	GoVersion     string         `json:"go_version"`
	BuildContext  *BuildContext  `json:"build_context,omitempty"`
	ModuleContext *ModuleContext `json:"module_context,omitempty"`
	Timestamp     string         `json:"timestamp,omitempty"`
	Platform      string         `json:"platform"`
}

// BuildContext captures build-time configuration
type BuildContext struct {
	Tags       []string          `json:"tags,omitempty"`
	CgoEnabled bool              `json:"cgo_enabled"`
	GOOS       string            `json:"goos"`
	GOARCH     string            `json:"goarch"`
	Compiler   string            `json:"compiler"`
	LDFlags    string            `json:"ldflags,omitempty"`
	GCFlags    string            `json:"gcflags,omitempty"`
	BuildFlags map[string]string `json:"build_flags,omitempty"`
}

// ModuleContext captures Go module metadata
type ModuleContext struct {
	GoModDigest    string             `json:"go_mod_digest,omitempty"`
	GoSumDigest    string             `json:"go_sum_digest,omitempty"`
	Vendored       bool               `json:"vendored"`
	VendorDigest   string             `json:"vendor_digest,omitempty"`
	ModuleProxy    string             `json:"module_proxy,omitempty"`
	Replaces       []ReplaceDirective `json:"replaces,omitempty"`
	RetractedCount int                `json:"retracted_count,omitempty"`
}

// ReplaceDirective documents a replace directive with risk assessment
type ReplaceDirective struct {
	Old       string `json:"old"`
	New       string `json:"new"`
	Type      string `json:"type"`       // "local-path", "version", "fork"
	RiskLevel string `json:"risk_level"` // "high", "medium", "low"
	Reason    string `json:"reason"`
}

// EnhanceCycloneDX adds goenv metadata to a CycloneDX SBOM
func (e *Enhancer) EnhanceCycloneDX(sbomPath string, opts EnhanceOptions) error {
	// Read the CycloneDX SBOM
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM: %w", err)
	}

	// Parse as generic JSON
	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Gather Go-aware metadata
	metadata, err := e.gatherMetadata(opts)
	if err != nil {
		return fmt.Errorf("failed to gather metadata: %w", err)
	}

	// Inject into metadata section
	if err := e.injectMetadata(sbom, metadata, opts); err != nil {
		return fmt.Errorf("failed to inject metadata: %w", err)
	}

	// Enhance components with Go-specific data
	if err := e.enhanceComponents(sbom, opts); err != nil {
		return fmt.Errorf("failed to enhance components: %w", err)
	}

	// Make deterministic if requested
	if opts.Deterministic {
		e.makeDeterministic(sbom)
	}

	// Write enhanced SBOM
	return e.writeSBOM(sbomPath, sbom, opts.Deterministic)
}

// gatherMetadata collects Go build and module context
func (e *Enhancer) gatherMetadata(opts EnhanceOptions) (*GoenvMetadata, error) {
	metadata := &GoenvMetadata{
		Platform: fmt.Sprintf("%s/%s", platform.OS(), platform.Arch()),
	}

	// Get current Go version
	if version, _, err := e.manager.GetCurrentVersion(); err == nil {
		metadata.GoVersion = version
	}

	// Set timestamp (use build time if deterministic)
	if opts.Deterministic {
		// Use a fixed timestamp based on go.mod mtime for reproducibility
		if modPath := filepath.Join(opts.ProjectDir, "go.mod"); utils.FileExists(modPath) {
			if info, err := os.Stat(modPath); err == nil {
				metadata.Timestamp = info.ModTime().UTC().Format(time.RFC3339)
			}
		}
	} else {
		metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Gather build context
	if buildCtx, err := e.gatherBuildContext(opts.ProjectDir); err == nil {
		metadata.BuildContext = buildCtx
	}

	// Gather module context
	if modCtx, err := e.gatherModuleContext(opts); err == nil {
		metadata.ModuleContext = modCtx
	}

	return metadata, nil
}

// gatherBuildContext extracts build configuration
func (e *Enhancer) gatherBuildContext(projectDir string) (*BuildContext, error) {
	ctx := &BuildContext{
		GOOS:     platform.OS(),
		GOARCH:   platform.Arch(),
		Compiler: "gc",
	}

	// Check CGO status from environment
	if cgo := os.Getenv("CGO_ENABLED"); cgo == "1" {
		ctx.CgoEnabled = true
	}

	// Extract build tags from environment or build files
	if tags := os.Getenv("GOFLAGS"); tags != "" {
		// Parse -tags flag from GOFLAGS
		parts := strings.Split(tags, " ")
		for i, part := range parts {
			if part == "-tags" && i+1 < len(parts) {
				ctx.Tags = strings.Split(parts[i+1], ",")
				break
			}
		}
	}

	// Get ldflags/gcflags if set
	ctx.LDFlags = os.Getenv("LDFLAGS")
	ctx.GCFlags = os.Getenv("GCFLAGS")

	return ctx, nil
}

// gatherModuleContext extracts Go module metadata
func (e *Enhancer) gatherModuleContext(opts EnhanceOptions) (*ModuleContext, error) {
	ctx := &ModuleContext{}

	projectDir := opts.ProjectDir
	if projectDir == "" {
		projectDir = "."
	}

	// Calculate go.mod digest
	if opts.EmbedDigests {
		if modPath := filepath.Join(projectDir, "go.mod"); utils.FileExists(modPath) {
			if hash, err := fileDigest(modPath); err == nil {
				ctx.GoModDigest = hash
			}
		}

		// Calculate go.sum digest
		if sumPath := filepath.Join(projectDir, "go.sum"); utils.FileExists(sumPath) {
			if hash, err := fileDigest(sumPath); err == nil {
				ctx.GoSumDigest = hash
			}
		}
	}

	// Check for vendoring
	vendorDir := filepath.Join(projectDir, "vendor")
	if utils.DirExists(vendorDir) {
		ctx.Vendored = true
		if opts.EmbedDigests {
			modulesPath := filepath.Join(vendorDir, "modules.txt")
			if utils.FileExists(modulesPath) {
				if hash, err := fileDigest(modulesPath); err == nil {
					ctx.VendorDigest = hash
				}
			}
		}
	}

	// Get module proxy
	if proxy := os.Getenv("GOPROXY"); proxy != "" && !opts.OfflineMode {
		ctx.ModuleProxy = proxy
	}

	// Parse replace directives
	if replaces, err := e.parseReplaceDirectives(projectDir); err == nil {
		ctx.Replaces = replaces
	}

	return ctx, nil
}

// parseReplaceDirectives extracts and classifies replace directives from go.mod
func (e *Enhancer) parseReplaceDirectives(projectDir string) ([]ReplaceDirective, error) {
	modPath := filepath.Join(projectDir, "go.mod")
	if !utils.FileExists(modPath) {
		return nil, nil
	}

	data, err := os.ReadFile(modPath)
	if err != nil {
		return nil, err
	}

	var directives []ReplaceDirective
	lines := strings.Split(string(data), "\n")
	inReplace := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track replace block
		if strings.HasPrefix(line, "replace (") {
			inReplace = true
			continue
		}
		if inReplace && line == ")" {
			inReplace = false
			continue
		}

		// Parse replace directive
		if strings.HasPrefix(line, "replace ") || (inReplace && line != "") {
			directive := e.parseReplaceLine(line)
			if directive != nil {
				directives = append(directives, *directive)
			}
		}
	}

	return directives, nil
}

// parseReplaceLine parses a single replace directive line
func (e *Enhancer) parseReplaceLine(line string) *ReplaceDirective {
	line = strings.TrimPrefix(line, "replace ")
	parts := strings.Split(line, "=>")
	if len(parts) != 2 {
		return nil
	}

	old := strings.TrimSpace(parts[0])
	new := strings.TrimSpace(parts[1])

	directive := &ReplaceDirective{
		Old: old,
		New: new,
	}

	// Classify type and risk
	if strings.HasPrefix(new, ".") || strings.HasPrefix(new, "/") {
		directive.Type = "local-path"
		directive.RiskLevel = "high"
		directive.Reason = "Local path dependency not subject to checksums"
	} else if strings.Contains(new, "github.com") && !strings.Contains(old, new) {
		directive.Type = "fork"
		directive.RiskLevel = "medium"
		directive.Reason = "Forked dependency - verify source"
	} else {
		directive.Type = "version"
		directive.RiskLevel = "low"
		directive.Reason = "Version override"
	}

	return directive
}

// injectMetadata adds goenv metadata to the SBOM
func (e *Enhancer) injectMetadata(sbom map[string]interface{}, metadata *GoenvMetadata, opts EnhanceOptions) error {
	// Get or create metadata section
	var metadataSection map[string]interface{}
	if meta, ok := sbom["metadata"].(map[string]interface{}); ok {
		metadataSection = meta
	} else {
		metadataSection = make(map[string]interface{})
		sbom["metadata"] = metadataSection
	}

	// Add goenv section
	metadataSection["goenv"] = metadata

	return nil
}

// enhanceComponents adds Go-specific data to individual components
func (e *Enhancer) enhanceComponents(sbom map[string]interface{}, opts EnhanceOptions) error {
	components, ok := sbom["components"].([]interface{})
	if !ok {
		components = []interface{}{}
	}

	// Add stdlib component if Go source files are present
	if stdlibComponent, err := e.createStdlibComponent(opts.ProjectDir); err == nil && stdlibComponent != nil {
		components = append(components, stdlibComponent)
	}

	// TODO: Mark replaced components
	// TODO: Add retracted version warnings

	sbom["components"] = components
	return nil
}

// createStdlibComponent analyzes Go source files and creates a stdlib component
func (e *Enhancer) createStdlibComponent(projectDir string) (map[string]interface{}, error) {
	if projectDir == "" {
		projectDir = "."
	}

	// Discover stdlib imports from Go source files
	stdlibImports, err := e.discoverStdlibImports(projectDir)
	if err != nil || len(stdlibImports) == 0 {
		return nil, err
	}

	// Get Go version for the component
	goVersion, _, err := e.manager.GetCurrentVersion()
	if err != nil {
		goVersion = "unknown"
	}

	// Create stdlib component in CycloneDX format
	component := map[string]interface{}{
		"type":        "library",
		"name":        "golang-stdlib",
		"version":     goVersion,
		"purl":        fmt.Sprintf("pkg:golang/stdlib@%s", goVersion),
		"bom-ref":     fmt.Sprintf("pkg:golang/stdlib@%s", goVersion),
		"description": fmt.Sprintf("Go standard library packages used by this project (%d packages)", len(stdlibImports)),
		"properties": []map[string]interface{}{
			{
				"name":  "goenv:stdlib_packages",
				"value": strings.Join(stdlibImports, ","),
			},
			{
				"name":  "goenv:stdlib_count",
				"value": fmt.Sprintf("%d", len(stdlibImports)),
			},
		},
	}

	return component, nil
}

// discoverStdlibImports scans Go source files for stdlib imports
func (e *Enhancer) discoverStdlibImports(projectDir string) ([]string, error) {
	stdlibSet := make(map[string]bool)

	// Walk through all .go files
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}

		// Skip vendor and hidden directories
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process .go files
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Parse the Go file
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil // Skip files with parse errors
		}

		// Extract imports
		for _, imp := range node.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)

			// Check if it's a stdlib package
			if e.isStdlibPackage(importPath) {
				stdlibSet[importPath] = true
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Convert set to sorted slice
	stdlibImports := make([]string, 0, len(stdlibSet))
	for pkg := range stdlibSet {
		stdlibImports = append(stdlibImports, pkg)
	}
	sort.Strings(stdlibImports)

	return stdlibImports, nil
}

// isStdlibPackage determines if an import path is from the Go standard library
func (e *Enhancer) isStdlibPackage(importPath string) bool {
	// Stdlib packages don't have dots in the first path element
	// (except for some special cases like golang.org/x/...)

	// Explicitly exclude known non-stdlib patterns
	if strings.HasPrefix(importPath, "github.com/") ||
		strings.HasPrefix(importPath, "golang.org/x/") ||
		strings.HasPrefix(importPath, "gopkg.in/") ||
		strings.HasPrefix(importPath, "go.uber.org/") ||
		strings.Contains(importPath, ".com/") ||
		strings.Contains(importPath, ".io/") ||
		strings.Contains(importPath, ".org/") ||
		strings.Contains(importPath, ".net/") {
		return false
	}

	// Internal packages are not stdlib for third-party projects
	if strings.HasPrefix(importPath, e.config.Root) {
		return false
	}

	// Common stdlib packages (non-exhaustive, covers major ones)
	firstSegment := importPath
	if idx := strings.Index(importPath, "/"); idx > 0 {
		firstSegment = importPath[:idx]
	}

	// Stdlib packages typically don't have dots
	return !strings.Contains(firstSegment, ".")
}

// makeDeterministic ensures reproducible output
func (e *Enhancer) makeDeterministic(sbom map[string]interface{}) {
	// Sort components by name
	if components, ok := sbom["components"].([]interface{}); ok {
		sort.Slice(components, func(i, j int) bool {
			ci := components[i].(map[string]interface{})
			cj := components[j].(map[string]interface{})
			nameI, _ := ci["name"].(string)
			nameJ, _ := cj["name"].(string)
			return nameI < nameJ
		})
		sbom["components"] = components
	}

	// Replace random UUID with deterministic one if present
	if metadata, ok := sbom["metadata"].(map[string]interface{}); ok {
		if component, ok := metadata["component"].(map[string]interface{}); ok {
			// Generate deterministic UUID based on component content
			if name, ok := component["name"].(string); ok {
				deterministicUUID := generateDeterministicUUID(name)
				component["bom-ref"] = deterministicUUID
				metadata["component"] = component
			}
		}
		sbom["metadata"] = metadata
	}
}

// writeSBOM writes the enhanced SBOM to disk
func (e *Enhancer) writeSBOM(path string, sbom map[string]interface{}, deterministic bool) error {
	var data []byte
	var err error

	if deterministic {
		// Use deterministic JSON encoding (no random map ordering)
		data, err = json.MarshalIndent(sbom, "", "  ")
	} else {
		data, err = json.MarshalIndent(sbom, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	return nil
}

// fileDigest computes SHA256 hash of a file
func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// generateDeterministicUUID creates a deterministic UUID from content
func generateDeterministicUUID(content string) string {
	hash := sha256.Sum256([]byte(content))
	// Format as UUID v5 style
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}

// ComputeSBOMDigest computes a normalized hash of an SBOM for reproducibility
func ComputeSBOMDigest(sbomPath, algorithm string) (string, error) {
	// Read SBOM
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SBOM: %w", err)
	}

	// Parse as JSON
	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return "", fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Normalize for reproducibility (remove timestamps, sort)
	normalized := normalizeSBOM(sbom)

	// Marshal to canonical JSON
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to marshal normalized SBOM: %w", err)
	}

	// Compute hash
	switch algorithm {
	case "sha256":
		hash := sha256.Sum256(canonical)
		return hex.EncodeToString(hash[:]), nil
	case "sha512":
		// Note: Would need crypto/sha512 import for this
		return "", fmt.Errorf("sha512 not yet implemented")
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// VerifyReproducible compares two SBOMs for reproducibility
func VerifyReproducible(sbom1Path, sbom2Path string) (match bool, diff string, err error) {
	// Compute normalized hashes
	hash1, err := ComputeSBOMDigest(sbom1Path, "sha256")
	if err != nil {
		return false, "", fmt.Errorf("failed to hash %s: %w", sbom1Path, err)
	}

	hash2, err := ComputeSBOMDigest(sbom2Path, "sha256")
	if err != nil {
		return false, "", fmt.Errorf("failed to hash %s: %w", sbom2Path, err)
	}

	// Compare hashes
	if hash1 == hash2 {
		return true, "", nil
	}

	// Generate diff information
	diff = fmt.Sprintf("Hash mismatch:\n  %s: %s\n  %s: %s",
		sbom1Path, hash1, sbom2Path, hash2)

	return false, diff, nil
}

// normalizeSBOM removes non-deterministic fields for comparison
func normalizeSBOM(sbom map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{})

	for key, value := range sbom {
		switch key {
		case "metadata":
			// Normalize metadata (remove timestamps)
			if meta, ok := value.(map[string]interface{}); ok {
				normalizedMeta := make(map[string]interface{})
				for k, v := range meta {
					if k != "timestamp" { // Exclude timestamp
						normalizedMeta[k] = v
					}
				}
				normalized[key] = normalizedMeta
			}
		case "components":
			// Sort components by name
			if components, ok := value.([]interface{}); ok {
				sorted := make([]interface{}, len(components))
				copy(sorted, components)
				sort.Slice(sorted, func(i, j int) bool {
					ci := sorted[i].(map[string]interface{})
					cj := sorted[j].(map[string]interface{})
					nameI, _ := ci["name"].(string)
					nameJ, _ := cj["name"].(string)
					return nameI < nameJ
				})
				normalized[key] = sorted
			}
		default:
			normalized[key] = value
		}
	}

	return normalized
}
