package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var bpmStandaloneGetPackage = getBPMPackage

func NewBPMCommand() *cobra.Command {
	buildFile := defaultBPMBuildFile
	buildVersion := ""
	buildKeysDir := defaultBPMBuildKeysDir

	cmd := &cobra.Command{
		Use:          "bpm",
		Short:        "An eBPF Package Manager",
		Args:         cobra.NoArgs,
		RunE:         func(cmd *cobra.Command, args []string) error { return cmd.Help() },
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newStandaloneBPMPullCommand(),
		newStandaloneBPMPushCommand(),
		newStandaloneBPMInfoCommand(),
		newStandaloneBPMKeyCommand(),
		newStandaloneBPMInstallCommand(),
		newStandaloneBPMListCommand(),
		newStandaloneBPMUninstallCommand(),
		newStandaloneBPMVersionCommand(),
		newStandaloneBPMBuildCommand(&buildFile, &buildVersion, &buildKeysDir),
	)

	return cmd
}

func ExecuteBPM() {
	if err := NewBPMCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newStandaloneBPMPullCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "pull <package-reference>",
		Short: "Pull an eBPF package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()

			_, err = bpmStandaloneGetPackage(ctx, args[0], ".", nil)
			if err != nil {
				return err
			}
			return nil
		},
	}
}

func newStandaloneBPMPushCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "push <package-file> <repository>",
		Short: "Push an eBPF package",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()

			ref, err := putBPMPackage(ctx, args[0], args[1], nil)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), ref)
			return nil
		},
	}
}

func newStandaloneBPMInfoCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "info <package-file|package-reference>",
		Short: "Print eBPF package README",
		Example: `  bpm info ./hello-bee-world-0.0.7.bee
  bpm info oci://quay.io/isovalent-dev/hello-bee-world:0.0.7`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return printBPMPackageReadme(cmd, args[0])
		},
	}
}

func newStandaloneBPMKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "key",
		Short:        "Manage eBPF package public keys",
		Args:         cobra.NoArgs,
		RunE:         func(cmd *cobra.Command, args []string) error { return cmd.Help() },
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newStandaloneBPMKeyAddCommand(),
		newStandaloneBPMKeyFingerprintCommand(),
		newStandaloneBPMKeyListCommand(),
	)

	return cmd
}

func newStandaloneBPMKeyAddCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "add <package-file|package-reference>",
		Short: "Add a trusted eBPF package public key",
		Example: `  bpm key add ./hello-bee-world-0.0.7.bee
  bpm key add oci://quay.io/isovalent-dev/hello-bee-world:0.0.7`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()

			result, err := addBPMKey(ctx, args[0], "", nil)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), result.Fingerprint)
			return nil
		},
	}
}

func newStandaloneBPMKeyFingerprintCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint <package-file|package-reference>",
		Short: "Print an eBPF package SPKI fingerprint",
		Example: `  bpm key fingerprint ./hello-bee-world-0.0.7.bee
  bpm key fingerprint oci://quay.io/isovalent-dev/hello-bee-world:0.0.7`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return printBPMPackageSPKIFingerprint(cmd, args[0])
		},
	}
}

func newStandaloneBPMKeyListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List trusted eBPF package public keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fingerprints, err := listBPMKeys("")
			if err != nil {
				return err
			}
			for _, fingerprint := range fingerprints {
				fmt.Fprintln(cmd.OutOrStdout(), fingerprint)
			}
			return nil
		},
	}
}

func newStandaloneBPMInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install <package-file|package-reference>",
		Short: "Install an eBPF package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()

			installDir, err := installBPMPackage(ctx, args[0], "", nil, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), installDir)
			return nil
		},
	}
}

func newStandaloneBPMListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List installed eBPF packages",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			packages, err := listBPMInstalledPackages("")
			if err != nil {
				return err
			}
			for _, pkg := range packages {
				fmt.Fprintln(cmd.OutOrStdout(), pkg)
			}
			return nil
		},
	}
}

func newStandaloneBPMUninstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall <package>",
		Short: "Uninstall an eBPF package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()

			installDir, err := uninstallBPMPackage(ctx, args[0], "", cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), installDir)
			return nil
		},
	}
}

func newStandaloneBPMVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print eBPF package manager version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version)
			return nil
		},
	}
}

func newStandaloneBPMBuildCommand(buildFile *string, buildVersion *string, buildKeysDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build [context]",
		Short: "Build an eBPF package",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()

			resolvedBuildFile, err := resolveBPMBuildFilePathFromFlag(cmd, args, *buildFile)
			if err != nil {
				return err
			}
			outputPath, err := runBPMBuild(ctx, resolvedBuildFile, *buildVersion, ".", *buildKeysDir, cmd.ErrOrStderr(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), outputPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(buildFile, "file", "f", defaultBPMBuildFile, "eBPF package build file")
	cmd.Flags().StringVar(buildVersion, "version", "", "eBPF package version")
	cmd.Flags().StringVar(buildKeysDir, "keys-dir", defaultBPMBuildKeysDir, "Shirudo signing keys directory")

	return cmd
}

func printBPMPackageReadme(cmd *cobra.Command, source string) error {
	ctx, cancel, err := commandContext(cmd)
	if err != nil {
		return err
	}
	defer cancel()

	info, err := infoBPMPackage(ctx, source, nil)
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), info.Readme)
	return nil
}

func printBPMPackageSPKIFingerprint(cmd *cobra.Command, source string) error {
	ctx, cancel, err := commandContext(cmd)
	if err != nil {
		return err
	}
	defer cancel()

	fingerprint, err := fingerprintBPMPackage(ctx, source, nil)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), fingerprint)
	return nil
}

func resolveBPMBuildFilePathFromFlag(cmd *cobra.Command, args []string, buildFile string) (string, error) {
	contextDir := "."
	if len(args) > 0 {
		contextDir = args[0]
	}

	return resolveBPMBuildFilePath(contextDir, buildFile, cmd.Flags().Changed("file"))
}
