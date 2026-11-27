#
# flake.nix - PCP Nix packaging
#
# Quick Start:
#   nix build                         # Build PCP package
#   nix develop                       # Development shell
#   nix flake show                    # List all outputs
#
# Run All Tests:
#   nix run .#pcp-test-all            # Container + K8s + MicroVM tests
#
# Individual Tests:
#   nix run .#pcp-container-test      # Docker/Podman lifecycle
#   nix run .#pcp-k8s-test            # Kubernetes DaemonSet (needs minikube)
#   nix run .#pcp-test-all-microvms   # All MicroVM variants
#
# K8s Manifests (no minikube needed):
#   nix build .#pcp-k8s-manifests          # All manifests + README
#   nix build .#pcp-k8s-manifest-daemonset # Individual DaemonSet YAML
#
# MicroVM with TAP networking (for Grafana dashboards):
#   nix run .#pcp-check-host                # Verify host environment
#   sudo nix run .#pcp-network-setup        # Create TAP bridge (requires sudo)
#   nix build .#pcp-microvm-grafana-tap && ./result/bin/microvm-run
#   # Access Grafana at http://10.177.0.20:3000
#   nix run .#pcp-vm-stop                   # Stop VM
#   sudo nix run .#pcp-network-teardown     # Cleanup (requires sudo)
#
# Cross-compile (on x86_64-linux), then copy to the board:
#   nix build .#pcp-riscv64                 # or .#pcp-aarch64
#   nix copy --no-check-sigs --to ssh-ng://root@<board> ./result
#
# See also: ./docs/HowTos/nix/index.rst
#
{
  description = "Performance Co-Pilot (PCP) - system performance monitoring toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      microvm,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        nixDir = ./build/nix;
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;

        # Import modular package definition
        # Pass self for stable source hashing - see build/nix/package.nix for details
        pcp = import (nixDir + "/package.nix") { inherit pkgs; src = self; };

        # Cross-compiled PCP for other 64-bit Linux architectures, built on
        # x86_64-linux with nixpkgs' cross toolchains (see build/nix/cross.nix).
        crossArches = lib.optionals (system == "x86_64-linux") [ "riscv64" "aarch64" ];
        crossPackages = lib.genAttrs' crossArches (arch:
          lib.nameValuePair "pcp-${arch}" (import (nixDir + "/cross.nix") {
            inherit nixpkgs system; src = self; crossSystem = "${arch}-linux";
          }));
        # Table-driven checks (build/nix/tests/cross-test.nix)
        crossTests = lib.genAttrs crossArches (arch:
          import (nixDir + "/tests/cross-test.nix") {
            inherit pkgs lib arch;
            pcpNative = pcp;
            pcpCross = crossPackages."pcp-${arch}";
          });

        # Import shared constants and variant definitions
        constants = import (nixDir + "/constants.nix");
        variants = import (nixDir + "/variants.nix") { inherit constants; };
        nixosModule = import (nixDir + "/nixos-module.nix");

        # ─── MicroVM Generator ───────────────────────────────────────────
        # Creates a MicroVM runner with the specified configuration.
        # See build/nix/microvm.nix for full parameter documentation.
        mkMicroVM = {
          networking ? "user",
          debugMode ? true,
          enablePmlogger ? true,
          enableEvalTools ? false,
          enablePmieTest ? false,
          enableGrafana ? false,
          enableBpf ? false,
          portOffset ? 0,
          variant ? "base",
        }:
          import (nixDir + "/microvm.nix") {
            inherit pkgs lib pcp microvm nixosModule nixpkgs system;
            inherit networking debugMode enablePmlogger enableEvalTools
                    enablePmieTest enableGrafana enableBpf
                    portOffset variant;
          };

        # ─── Variant Package Generator ───────────────────────────────────
        # Generates MicroVM packages for all variants and networking modes.
        mkVariantPackages = lib.foldl' (acc: variantName:
          let
            def = variants.definitions.${variantName};
            portOffset = constants.variantPortOffsets.${variantName};

            # User-mode networking variant
            userPkg = {
              name = variants.mkPackageName variantName "user";
              value = mkMicroVM ({
                networking = "user";
                inherit portOffset;
                variant = variantName;
              } // def.config);
            };

            # TAP networking variant (if supported)
            tapPkg = lib.optionalAttrs def.supportsTap {
              name = variants.mkPackageName variantName "tap";
              value = mkMicroVM ({
                networking = "tap";
                inherit portOffset;
                variant = variantName;
              } // def.config);
            };
          in
            acc // { ${userPkg.name} = userPkg.value; }
            // lib.optionalAttrs (tapPkg ? name) { ${tapPkg.name} = tapPkg.value; }
        ) {} variants.variantNames;

        # Import lifecycle testing framework (Linux only)
        lifecycle = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import (nixDir + "/lifecycle") { inherit pkgs lib; }
        );

        # Import container module (Linux only) - returns { image, inputsHash }
        containerModule = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import (nixDir + "/container.nix") { inherit pkgs pcp; }
        );

        # Import container testing framework (Linux only)
        containerTest = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import (nixDir + "/container-test") {
            inherit pkgs lib pcp;
            containerInputsHash = containerModule.inputsHash or "";
          }
        );

        # Import Kubernetes testing framework (Linux only)
        k8sTest = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import (nixDir + "/k8s-test") {
            inherit pkgs lib pcp;
            containerInputsHash = containerModule.inputsHash or "";
          }
        );

        # Import standalone K8s manifest generator (Linux only)
        k8sManifests = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import (nixDir + "/k8s-manifests") { inherit pkgs lib; }
        );

        # Import test-all runner (Linux only)
        testAll = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import (nixDir + "/test-all") {
            inherit pkgs lib containerTest k8sTest;
          }
        );

      in
      {
        packages = {
          default = pcp;
          inherit pcp;
        } // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          {
            # OCI container image (Linux only)
            pcp-container = containerModule.image;
          }
          # MicroVM packages for all variants
          // mkVariantPackages
          # Lifecycle testing packages
          // lifecycle.packages
          # Container testing packages
          // containerTest.packages
          # Kubernetes testing packages
          // k8sTest.packages
          # Standalone K8s manifests
          // k8sManifests.packages
          # Test-all runner
          // testAll.packages
          # Cross-compiled packages (x86_64-linux build host only)
          // crossPackages
        );

        checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          vm-test = import (nixDir + "/vm-test.nix") {
            inherit pkgs pcp;
          };
        } // lib.optionalAttrs (crossTests ? riscv64) {
          cross-riscv64 = crossPackages.pcp-riscv64;
          cross-riscv64-smoke = crossTests.riscv64.smoke;
        };

        # Import modular development shell
        devShells.default = import (nixDir + "/shell.nix") { inherit pkgs pcp; };

        # ─── Apps (Linux only) ─────────────────────────────────────────────
        apps = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          let
            networkScripts = import (nixDir + "/network-setup.nix") { inherit pkgs; };
            vmScripts = import (nixDir + "/microvm-scripts.nix") { inherit pkgs; };

            # ─── MicroVM Test Apps ────────────────────────────────────────────
            # Generate test apps for each variant
            mkTestApp = variant: networkMode:
              let
                testName = variants.mkTestAppName variant networkMode;
                isTap = networkMode == "tap";
                portOffset = constants.variantPortOffsets.${variant};
                sshPort = constants.ports.sshForward + portOffset;
                host = if isTap then constants.network.vmIp else "localhost";
              in {
                name = testName;
                value = {
                  type = "app";
                  program = "${import (nixDir + "/tests/microvm-test.nix") {
                    inherit pkgs lib;
                    variant = "${variant}-${networkMode}";
                    inherit host sshPort;
                  }}/bin/pcp-test-${variant}-${networkMode}";
                };
              };

            # Generate test apps for all variants
            testApps = lib.foldl' (acc: variantName:
              let
                def = variants.definitions.${variantName};
                userTest = mkTestApp variantName "user";
                tapTest = lib.optionalAttrs def.supportsTap (mkTestApp variantName "tap");
              in
                acc // { ${userTest.name} = userTest.value; }
                // lib.optionalAttrs (tapTest ? name) { ${tapTest.name} = tapTest.value; }
            ) {} variants.variantNames;

          in {
            # Network management
            pcp-check-host = {
              type = "app";
              program = "${networkScripts.check}/bin/pcp-check-host";
            };
            pcp-network-setup = {
              type = "app";
              program = "${networkScripts.setup}/bin/pcp-network-setup";
            };
            pcp-network-teardown = {
              type = "app";
              program = "${networkScripts.teardown}/bin/pcp-network-teardown";
            };
            # VM management
            pcp-vm-check = {
              type = "app";
              program = "${vmScripts.check}/bin/pcp-vm-check";
            };
            pcp-vm-stop = {
              type = "app";
              program = "${vmScripts.stop}/bin/pcp-vm-stop";
            };
            pcp-vm-ssh = {
              type = "app";
              program = "${vmScripts.ssh}/bin/pcp-vm-ssh";
            };
            # Comprehensive test runner
            pcp-test-all-microvms = {
              type = "app";
              program = "${import (nixDir + "/tests/test-all-microvms.nix") { inherit pkgs lib; }}/bin/pcp-test-all-microvms";
            };
          }
          # Per-variant test apps
          // testApps
          # Lifecycle testing apps
          // lifecycle.apps
          # Container testing apps
          // containerTest.apps
          # Kubernetes testing apps
          // k8sTest.apps
          # Test-all runner
          // testAll.apps
          # Cross-package board tests: nix run .#pcp-cross-test-<arch> -- <host>
          // lib.mapAttrs' (arch: t: lib.nameValuePair "pcp-cross-test-${arch}" {
            type = "app";
            program = lib.getExe t.app;
          }) crossTests
        );
      }
    );
}
