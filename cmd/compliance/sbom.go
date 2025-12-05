package compliance

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	cmdpkg "github.com/go-nv/goenv/cmd"

	"github.com/go-nv/goenv/internal/cmdutil"
	"github.com/go-nv/goenv/internal/config"
	"github.com/go-nv/goenv/internal/errors"
	"github.com/go-nv/goenv/internal/manager"
	"github.com/go-nv/goenv/internal/platform"
	"github.com/go-nv/goenv/internal/resolver"
	"github.com/go-nv/goenv/internal/sbom"
	"github.com/go-nv/goenv/internal/utils"
	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:     "sbom",
	Short:   "Generate Software Bill of Materials for projects",
	GroupID: string(cmdpkg.GroupTools),
	Long: `Generate SBOMs using industry-standard tools (cyclonedx-gomod, syft) with goenv-managed toolchains.

CURRENT STATE (v3.0): This is a convenience wrapper that runs SBOM tools with the 
correct Go version and environment. It does NOT generate SBOMs itself or add features
beyond what the underlying tools provide.

ROADMAP: Future versions will add validation, policy enforcement, signing, vulnerability
scanning, and compliance reporting. See docs/roadmap/SBOM_ROADMAP.md for details.

ALTERNATIVE: Advanced users can run SBOM tools directly:
  goenv exec cyclonedx-gomod -json -output sbom.json

Examples:
  # Generate CycloneDX SBOM for current project
  goenv sbom project --tool=cyclonedx-gomod --format=cyclonedx-json

  # Generate SPDX SBOM with syft
  goenv sbom project --tool=syft --format=spdx-json --output=sbom.spdx.json

  # Generate SBOM for container image
  goenv sbom project --tool=syft --image=ghcr.io/myapp:v1.0.0

Before using, install the required tool:
  goenv tools install cyclonedx-gomod@v1.6.0
  goenv tools install syft@v1.0.0`,
}

var sbomProjectCmd = &cobra.Command{
	Use:   "project",
	Short: "Generate SBOM for a Go project",
	Long: `Generate a Software Bill of Materials for a Go project using cyclonedx-gomod or syft.

WHAT THIS DOES:
- Runs SBOM tools with the correct Go version and environment
- Provides unified CLI across different SBOM tools
- Ensures reproducibility in CI/CD pipelines

WHAT THIS DOES NOT DO (yet):
- Validate SBOM format or completeness (planned: v3.1)
- Sign or attest SBOMs (planned: v3.2)
- Scan for vulnerabilities (planned: v3.5)
- Enforce policies (planned: v3.1)

See docs/roadmap/SBOM_ROADMAP.md for planned features.

Supported tools:
- cyclonedx-gomod: Native Go module SBOM generator (CycloneDX format)
- syft: Multi-language SBOM generator (supports containers)`,
	RunE: runSBOMProject,
}

var (
	sbomTool          string
	sbomFormat        string
	sbomOutput        string
	sbomDir           string
	sbomImage         string
	sbomModulesOnly   bool
	sbomOffline       bool
	sbomToolArgs      string
	sbomDeterministic bool
	sbomEmbedDigests  bool
	sbomEnhance       bool
)

func init() {
	sbomProjectCmd.Flags().StringVar(&sbomTool, "tool", "cyclonedx-gomod", "SBOM tool to use (cyclonedx-gomod, syft)")
	sbomProjectCmd.Flags().StringVar(&sbomFormat, "format", "cyclonedx-json", "Output format (cyclonedx-json, spdx-json)")
	sbomProjectCmd.Flags().StringVarP(&sbomOutput, "output", "o", "sbom.json", "Output file path")
	sbomProjectCmd.Flags().StringVar(&sbomDir, "dir", ".", "Project directory to scan")
	sbomProjectCmd.Flags().StringVar(&sbomImage, "image", "", "Container image to scan (syft only)")
	sbomProjectCmd.Flags().BoolVar(&sbomModulesOnly, "modules-only", false, "Only scan Go modules (cyclonedx-gomod)")
	sbomProjectCmd.Flags().BoolVar(&sbomOffline, "offline", false, "Offline mode - avoid network access")
	sbomProjectCmd.Flags().StringVar(&sbomToolArgs, "tool-args", "", "Additional arguments to pass to the tool")
	sbomProjectCmd.Flags().BoolVar(&sbomEnhance, "enhance", true, "Add Go-aware metadata to SBOM (default true)")
	sbomProjectCmd.Flags().BoolVar(&sbomDeterministic, "deterministic", false, "Generate deterministic/reproducible SBOM")
	sbomProjectCmd.Flags().BoolVar(&sbomEmbedDigests, "embed-digests", false, "Embed go.mod/go.sum digests for reproducibility")

	sbomCmd.AddCommand(sbomProjectCmd)
	sbomCmd.AddCommand(sbomHashCmd)
	sbomCmd.AddCommand(sbomVerifyCmd)
	sbomCmd.AddCommand(sbomValidateCmd)
	cmdpkg.RootCmd.AddCommand(sbomCmd)
}

var sbomHashCmd = &cobra.Command{
	Use:   "hash <sbom-file>",
	Short: "Compute digest of an SBOM file",
	Long: `Compute a cryptographic hash of an SBOM file for reproducibility verification.

This command normalizes the SBOM (sorting components, normalizing whitespace) before
computing the digest to ensure consistent hashing across different generation runs.

The digest can be used to verify that two SBOMs have identical semantic content,
even if they were generated at different times or with different metadata timestamps.

Examples:
  # Compute hash of an SBOM
  goenv sbom hash sbom.json

  # Compute hash with specific algorithm
  goenv sbom hash sbom.json --algorithm=sha512`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOMHash,
}

var sbomVerifyCmd = &cobra.Command{
	Use:   "verify-reproducible <sbom1> <sbom2>",
	Short: "Verify two SBOMs have identical reproducible content",
	Long: `Compare two SBOM files to verify they have identical semantic content.

This command normalizes both SBOMs (removing timestamps, sorting components) and
compares their content digests to verify reproducibility. Exit code 0 indicates
the SBOMs are identical, non-zero indicates differences.

This is useful for:
- Verifying deterministic SBOM generation in CI/CD
- Detecting unexpected changes in dependencies
- Validating reproducible builds

Examples:
  # Compare two SBOMs
  goenv sbom verify-reproducible sbom1.json sbom2.json

  # Verify with detailed diff output
  goenv sbom verify-reproducible sbom1.json sbom2.json --diff`,
	Args: cobra.ExactArgs(2),
	RunE: runSBOMVerify,
}

var sbomValidateCmd = &cobra.Command{
	Use:   "validate <sbom-file>",
	Short: "Validate SBOM against policy rules",
	Long: `Validate an SBOM file against defined policy rules.

Policy files are YAML documents that define validation rules for:
- Supply chain security (replace directives, vendoring)
- Security requirements (CGO status, retracted versions)
- Completeness checks (required components, metadata)
- License compliance (allowed/blocked licenses)

Examples:
  # Validate with default policy
  goenv sbom validate sbom.json --policy=.goenv-policy.yaml

  # Validate and fail on warnings
  goenv sbom validate sbom.json --policy=policy.yaml --fail-on-warning

  # Validate with verbose output
  goenv sbom validate sbom.json --policy=policy.yaml --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOMValidate,
}

var (
	hashAlgorithm   string
	verifyDiff      bool
	policyFile      string
	failOnWarning   bool
	verboseValidate bool
)

func init() {
	sbomHashCmd.Flags().StringVar(&hashAlgorithm, "algorithm", "sha256", "Hash algorithm (sha256, sha512)")
	sbomVerifyCmd.Flags().BoolVar(&verifyDiff, "diff", false, "Show detailed differences if SBOMs don't match")
	sbomValidateCmd.Flags().StringVarP(&policyFile, "policy", "p", ".goenv-policy.yaml", "Path to policy configuration file")
	sbomValidateCmd.Flags().BoolVar(&failOnWarning, "fail-on-warning", false, "Treat warnings as failures")
	sbomValidateCmd.Flags().BoolVar(&verboseValidate, "verbose", false, "Show detailed validation output")
}

func runSBOMHash(cmd *cobra.Command, args []string) error {
	sbomPath := args[0]

	// Verify file exists
	if !utils.FileExists(sbomPath) {
		return fmt.Errorf("SBOM file not found: %s", sbomPath)
	}

	// Compute hash using the enhancer's deterministic logic
	ctx := cmdutil.GetContexts(cmd)
	cfg := ctx.Config

	hash, err := sbom.ComputeSBOMDigest(sbomPath, hashAlgorithm)
	if err != nil {
		return errors.FailedTo("compute SBOM digest", err)
	}

	// Output hash in format: <algorithm>:<hex-digest>
	if cfg.Debug {
		fmt.Fprintf(cmd.OutOrStdout(), "%s:%s  %s\n", hashAlgorithm, hash, sbomPath)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s:%s\n", hashAlgorithm, hash)
	}

	return nil
}

func runSBOMVerify(cmd *cobra.Command, args []string) error {
	sbom1Path := args[0]
	sbom2Path := args[1]

	// Verify both files exist
	if !utils.FileExists(sbom1Path) {
		return fmt.Errorf("SBOM file not found: %s", sbom1Path)
	}
	if !utils.FileExists(sbom2Path) {
		return fmt.Errorf("SBOM file not found: %s", sbom2Path)
	}

	// Compare SBOMs
	ctx := cmdutil.GetContexts(cmd)

	cfg := ctx.Config
	match, diff, err := sbom.VerifyReproducible(sbom1Path, sbom2Path)
	if err != nil {
		return errors.FailedTo("verify reproducibility", err)
	}

	if match {
		fmt.Fprintf(cmd.OutOrStdout(), "✓ SBOMs are reproducibly identical\n")
		if cfg.Debug {
			fmt.Fprintf(cmd.ErrOrStderr(), "Debug: %s == %s\n", sbom1Path, sbom2Path)
		}
		return nil
	}

	// SBOMs don't match
	fmt.Fprintf(cmd.ErrOrStderr(), "✗ SBOMs differ\n")
	if verifyDiff {
		fmt.Fprintf(cmd.OutOrStdout(), "\nDifferences:\n%s\n", diff)
	}

	return fmt.Errorf("SBOMs are not reproducibly identical")
}

func runSBOMValidate(cmd *cobra.Command, args []string) error {
	sbomPath := args[0]

	// Verify SBOM file exists
	if !utils.FileExists(sbomPath) {
		return fmt.Errorf("SBOM file not found: %s", sbomPath)
	}

	// Verify policy file exists
	if !utils.FileExists(policyFile) {
		return fmt.Errorf("policy file not found: %s (use --policy to specify)", policyFile)
	}

	cfg, _ := cmdutil.SetupContext()

	// Load policy engine
	engine, err := sbom.NewPolicyEngine(policyFile)
	if err != nil {
		return errors.FailedTo("load policy", err)
	}

	if cfg.Debug || verboseValidate {
		fmt.Fprintf(cmd.ErrOrStderr(), "goenv: Validating %s against policy %s\n", sbomPath, policyFile)
	}

	// Run validation
	result, err := engine.Validate(sbomPath)
	if err != nil {
		return errors.FailedTo("validate SBOM", err)
	}

	// Output results
	if verboseValidate {
		fmt.Fprint(cmd.OutOrStdout(), result.Summary)

		// Show detailed violations
		if len(result.Violations) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "\nViolations:\n")
			for i, v := range result.Violations {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%d. %s\n", i+1, v.Rule)
				fmt.Fprintf(cmd.OutOrStdout(), "   Severity: %s\n", v.Severity)
				fmt.Fprintf(cmd.OutOrStdout(), "   Component: %s\n", v.Component)
				fmt.Fprintf(cmd.OutOrStdout(), "   Message: %s\n", v.Message)
				if v.Remediation != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "   Remediation: %s\n", v.Remediation)
				}
			}
		}

		if len(result.Warnings) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "\nWarnings:\n")
			for i, w := range result.Warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%d. %s\n", i+1, w.Rule)
				fmt.Fprintf(cmd.OutOrStdout(), "   Severity: %s\n", w.Severity)
				fmt.Fprintf(cmd.OutOrStdout(), "   Component: %s\n", w.Component)
				fmt.Fprintf(cmd.OutOrStdout(), "   Message: %s\n", w.Message)
				if w.Remediation != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "   Remediation: %s\n", w.Remediation)
				}
			}
		}
	} else {
		// Concise output
		if result.Passed {
			fmt.Fprintf(cmd.OutOrStdout(), "✓ SBOM validation passed\n")
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "✗ SBOM validation failed\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "  %d violations, %d warnings\n",
				len(result.Violations), len(result.Warnings))
			fmt.Fprintf(cmd.ErrOrStderr(), "  Run with --verbose for details\n")
		}
	}

	// Return error if validation failed
	if !result.Passed {
		if failOnWarning && len(result.Warnings) > 0 {
			return fmt.Errorf("validation failed with %d violations and %d warnings",
				len(result.Violations), len(result.Warnings))
		}
		return fmt.Errorf("validation failed with %d violations", len(result.Violations))
	}

	return nil
}

func runSBOMProject(cmd *cobra.Command, args []string) error {
	ctx := cmdutil.GetContexts(cmd)
	cfg := ctx.Config
	mgr := ctx.Manager
	env := ctx.Environment

	// Validate flags
	if sbomImage != "" && sbomDir != "." {
		return fmt.Errorf("cannot specify both --image and --dir")
	}

	if sbomImage != "" && sbomTool != "syft" {
		return fmt.Errorf("--image is only supported with --tool=syft")
	}

	// Get current Go version for provenance and tool resolution
	goVersion, versionSource, err := mgr.GetCurrentVersion()
	if err != nil {
		goVersion = "unknown"
	}

	// Resolve tool path using version context
	toolPath, err := resolveSBOMTool(cfg, env, sbomTool, goVersion, versionSource)
	if err != nil {
		return err
	}

	// Print provenance header to stderr (safe for CI logs)
	fmt.Fprintf(cmd.ErrOrStderr(), "goenv: Generating SBOM with %s (Go %s, %s/%s)\n",
		sbomTool, goVersion, platform.OS(), platform.Arch())

	// Build command based on tool
	var toolCmd *exec.Cmd
	switch sbomTool {
	case "cyclonedx-gomod":
		toolCmd, err = buildCycloneDXCommand(toolPath, cfg)
	case "syft":
		toolCmd, err = buildSyftCommand(toolPath, cfg)
	default:
		return fmt.Errorf("unsupported tool: %s (supported: cyclonedx-gomod, syft)", sbomTool)
	}

	if err != nil {
		return errors.FailedTo("build command", err)
	}

	// Set up environment
	toolCmd.Env = os.Environ()
	if sbomOffline {
		// Add offline flags if supported by tool
		// Most tools respect GOPROXY=off
		toolCmd.Env = append(toolCmd.Env, "GOPROXY=off")
	}

	// Connect output
	toolCmd.Stdout = cmd.OutOrStdout()
	toolCmd.Stderr = cmd.ErrOrStderr()

	// Run tool
	if cfg.Debug {
		fmt.Fprintf(cmd.ErrOrStderr(), "Debug: Running command: %s\n", strings.Join(toolCmd.Args, " "))
	}

	if err := toolCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Preserve tool's exit code
			os.Exit(exitErr.ExitCode())
		}
		return errors.FailedTo("execute tool", err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "goenv: SBOM written to %s\n", sbomOutput)

	// Enhance SBOM with Go-aware metadata if enabled
	if sbomEnhance && (sbomTool == "cyclonedx-gomod" || sbomFormat == "cyclonedx-json") {
		if err := enhanceSBOM(cfg, mgr, cmd); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "goenv: Warning: Failed to enhance SBOM: %v\n", err)
			// Don't fail - enhancement is optional
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "goenv: SBOM enhanced with Go-aware metadata\n")
		}
	}

	return nil
}

// enhanceSBOM adds Go-specific metadata to the generated SBOM
func enhanceSBOM(cfg *config.Config, mgr *manager.Manager, cmd *cobra.Command) error {
	// Import the enhancer package
	enhancer := sbom.NewEnhancer(cfg, mgr)

	opts := sbom.EnhanceOptions{
		ProjectDir:    sbomDir,
		Deterministic: sbomDeterministic,
		OfflineMode:   sbomOffline,
		EmbedDigests:  sbomEmbedDigests || sbomDeterministic, // Always embed if deterministic
	}

	return enhancer.EnhanceCycloneDX(sbomOutput, opts)
}

// resolveSBOMTool finds the tool binary in goenv-managed paths
func resolveSBOMTool(cfg *config.Config, env *utils.GoenvEnvironment, tool, version, versionSource string) (string, error) {
	// Use resolver to respect local vs global context
	sbomTools := map[string]string{
		"cyclonedx-gomod": "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod",
		"syft":            "github.com/anchore/syft/cmd/syft",
	}

	r := resolver.New(cfg, env)

	if version != "unknown" && version != "" {
		if toolPath, err := r.ResolveBinary(tool, version, versionSource); err == nil {
			return toolPath, nil
		}
	}

	// Fallback: Check if tool is in PATH (system-wide installation)
	if path, err := exec.LookPath(tool); err == nil {
		return path, nil
	}

	goTool, ok := sbomTools[tool]
	if !ok {
		return "", fmt.Errorf("unsupported SBOM tool: %s", tool)
	}

	goTool = fmt.Sprintf("%s@latest", goTool)

	fmt.Printf("goenv: %s not found in goenv-managed paths or system PATH. Attempting to install...\n", tool)

	cmd := exec.Command("goenv", "tools", "install", goTool)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err == nil {
		// Retry finding the tool after installation; it will be rehashed into the shims automatically
		if toolPath, err := r.ResolveBinary(tool, version, versionSource); err == nil {
			return toolPath, nil
		}
	} else {
		return "", fmt.Errorf("goenv: Failed to install %s: %w", tool, err)
	}

	// Tool not found - provide actionable error
	return "", fmt.Errorf(`%s not found

To install:
  goenv tools install %s

Or install system-wide with:
  go install %s`, tool, goTool, goTool)
}

// buildCycloneDXCommand builds the cyclonedx-gomod command
func buildCycloneDXCommand(toolPath string, cfg *config.Config) (*exec.Cmd, error) {
	args := []string{}

	// Use the "mod" subcommand for module SBOMs (default behavior)
	// "mod" generates SBOMs for modules, including all packages
	// "app" would be for application binaries, "bin" for pre-built binaries
	args = append(args, "mod")

	// Output file - new format uses -output (with single dash)
	args = append(args, "-output", sbomOutput)

	// Format - newer versions use -output-format flag
	if sbomFormat == "cyclonedx-json" {
		args = append(args, "-json")
	} else if sbomFormat != "cyclonedx-xml" {
		return nil, fmt.Errorf("cyclonedx-gomod only supports cyclonedx-json and cyclonedx-xml formats")
	}

	// Modules only (include licenses and set type)
	if sbomModulesOnly {
		args = append(args, "-licenses", "-type", "library")
	}

	// Additional tool args
	if sbomToolArgs != "" {
		args = append(args, strings.Fields(sbomToolArgs)...)
	}

	cmdExec := exec.Command(toolPath, args...)
	cmdExec.Dir = sbomDir

	return cmdExec, nil
}

// buildSyftCommand builds the syft command
func buildSyftCommand(toolPath string, cfg *config.Config) (*exec.Cmd, error) {
	args := []string{}

	// Scan target (image or directory)
	target := sbomDir
	if sbomImage != "" {
		target = sbomImage
	}
	args = append(args, target)

	// Output format
	outputFormat := "cyclonedx-json"
	switch sbomFormat {
	case "cyclonedx-json":
		outputFormat = "cyclonedx-json"
	case "spdx-json":
		outputFormat = "spdx-json"
	case "syft-json":
		outputFormat = "json"
	default:
		return nil, fmt.Errorf("unsupported format for syft: %s", sbomFormat)
	}
	args = append(args, "-o", fmt.Sprintf("%s=%s", outputFormat, sbomOutput))

	// Quiet mode (reduce noise)
	args = append(args, "-q")

	// Additional tool args
	if sbomToolArgs != "" {
		args = append(args, strings.Fields(sbomToolArgs)...)
	}

	return exec.Command(toolPath, args...), nil
}
