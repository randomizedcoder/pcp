#
# flake.nix - PCP Nix packaging
#
# For comprehensive documentation including modular architecture, feature flags,
# technical details, and troubleshooting, see:
#
#   docs/HowTos/nix/index.rst
#
# ─── Quick Start: MicroVM ───────────────────────────────────────────────────
#
# Build and run a MicroVM (password auth enabled, root:pcp):
#
#   nix build .#pcp-microvm -o result-microvm
#   ./result-microvm/bin/microvm-run
#
# In another terminal, manage the VM:
#
#   nix run .#pcp-vm-check   # List running PCP MicroVMs (any variant)
#   nix run .#pcp-vm-ssh     # SSH into VM as root (password: pcp)
#   nix run .#pcp-vm-stop    # Stop all running PCP MicroVMs (any variant)
#
# These management scripts work with ALL MicroVM variants - they detect VMs by
# hostname pattern (pcp-vm, pcp-eval-vm, pcp-grafana-vm, pcp-bpf-vm).
#
# ─── MicroVM Variants (7 total) ───────────────────────────────────────────────
#
# Base VMs (PCP services: pmcd, pmlogger, pmproxy):
#   .#pcp-microvm            - User-mode networking
#   .#pcp-microvm-tap        - TAP networking (direct access at 10.177.0.20)
#
# Evaluation VMs (+ node_exporter, below, pmie testing):
#   .#pcp-microvm-eval       - User-mode networking
#   .#pcp-microvm-eval-tap   - TAP networking
#
# Grafana VMs (+ Prometheus + Grafana + BPF dashboards):
#   .#pcp-microvm-grafana     - Grafana at localhost:13000 (includes BPF metrics)
#   .#pcp-microvm-grafana-tap - Grafana at 10.177.0.20:3000 (includes BPF metrics)
#
# eBPF VMs (advanced kernel tracing):
#   .#pcp-microvm-bpf        - Pre-compiled CO-RE eBPF (fast, 1GB)
#   NOTE: BCC is deprecated - use BPF PMDA instead (CO-RE eBPF)
#
# All variants have debugMode=true by default (password SSH for testing).
#
# TAP networking requires host setup first:
#   nix run .#pcp-network-setup    # Create bridge and TAP device
#   nix run .#pcp-network-teardown # Remove bridge and TAP device
#
# ─── File Structure ─────────────────────────────────────────────────────────
#
#   flake.nix              - This file (orchestrator)
#   nix/package.nix        - PCP derivation with version from VERSION.pcp
#   nix/constants.nix      - Shared configuration constants
#   nix/nixos-module.nix   - NixOS module for PCP services
#   nix/grafana.nix        - NixOS module for Grafana with PCP dashboards
#   nix/microvm.nix        - Parametric MicroVM configuration
#   nix/microvm-scripts.nix - VM management scripts (check, stop, ssh)
#   nix/bpf.nix            - NixOS module for BPF PMDA
#   nix/bcc.nix            - NixOS module for BCC PMDA (DEPRECATED)
#   nix/pmie-test.nix      - pmie testing module (stress-ng workload)
#   nix/container.nix      - OCI container image
#   nix/network-setup.nix  - TAP/bridge network setup scripts
#   nix/test-lib.nix       - Shared test functions
#   nix/tests/             - MicroVM test scripts
#   nix/vm-test.nix        - NixOS VM integration test
#   nix/lifecycle/         - Modular lifecycle testing framework
#
# ─── Lifecycle Testing ────────────────────────────────────────────────────────
#
# The lifecycle testing framework provides fine-grained control over MicroVM
# validation with 7 distinct phases. Each phase can be run individually for
# debugging, or as a complete test via the full-test scripts.
#
# Lifecycle Phases:
#   Phase 0: Build VM       - Build the MicroVM derivation
#   Phase 1: Start VM       - Start QEMU process, verify it's running
#   Phase 2: Serial Console - Verify ttyS0 console is responsive
#   Phase 2b: Virtio Console - Verify hvc0 console is responsive
#   Phase 3: Verify Services - Check PCP services via SSH (pmcd, pmproxy, etc.)
#   Phase 4: Verify Metrics  - Check pminfo returns data for key metrics
#   Phase 5: Shutdown        - Send poweroff command via console
#   Phase 6: Wait Exit       - Wait for VM process to exit cleanly
#
# Full lifecycle tests (recommended):
#   nix run .#pcp-lifecycle-full-test-base        # Test base variant
#   nix run .#pcp-lifecycle-full-test-eval        # Test eval variant
#   nix run .#pcp-lifecycle-full-test-grafana     # Test grafana variant
#   nix run .#pcp-lifecycle-full-test-grafana-tap # Test grafana with TAP networking
#   nix run .#pcp-lifecycle-full-test-bpf         # Test BPF variant
#   nix run .#pcp-lifecycle-test-all              # Test all variants sequentially
#   nix run .#pcp-lifecycle-test-all -- --only=bpf        # Test specific variant
#   nix run .#pcp-lifecycle-test-all -- --only=grafana-tap # Test TAP variant
#
# Utility scripts (for debugging):
#   nix run .#pcp-lifecycle-status-base       # Check VM status (process/consoles)
#   nix run .#pcp-lifecycle-force-kill-base   # Force kill stuck VM
#
# See nix/lifecycle/ for implementation details and docs/HowTos/nix/index.rst
# for comprehensive documentation.
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
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;

        # Import PCP package (version derived from VERSION.pcp)
        pcp = import ./nix/package.nix { inherit pkgs; };

        # Import shared modules
        nixosModule = import ./nix/nixos-module.nix;
        constants = import ./nix/constants.nix;

        # MicroVM generator function
        # Creates a MicroVM with the specified configuration
        mkMicroVM = args: import ./nix/microvm.nix ({
          inherit pkgs lib pcp microvm nixosModule nixpkgs system;
        } // args);
      in
      {
        packages = {
          default = pcp;
          inherit pcp;
        } // lib.optionalAttrs pkgs.stdenv.isLinux {
          # ─── Base VMs ─────────────────────────────────────────────────────
          # PCP services only: pmcd, pmlogger, pmproxy
          # Port offset: 0 (SSH: 22022, pmcd: 44321, pmproxy: 44322)
          # Console: serial=24500, virtio=24501
          pcp-microvm = mkMicroVM {
            variant = "base";
            portOffset = constants.variantPortOffsets.base;
          };
          pcp-microvm-tap = mkMicroVM {
            variant = "base";
            networking = "tap";
            portOffset = constants.variantPortOffsets.base;
          };

          # ─── Evaluation VMs ───────────────────────────────────────────────
          # Base + node_exporter, below, pmie testing
          # Port offset: 100 (SSH: 22122, pmcd: 44421, pmproxy: 44422)
          # Console: serial=24510, virtio=24511
          pcp-microvm-eval = mkMicroVM {
            variant = "eval";
            enablePmlogger = false;
            enableEvalTools = true;
            enablePmieTest = true;
            portOffset = constants.variantPortOffsets.eval;
          };
          pcp-microvm-eval-tap = mkMicroVM {
            variant = "eval";
            networking = "tap";
            enablePmlogger = false;
            enableEvalTools = true;
            enablePmieTest = true;
            portOffset = constants.variantPortOffsets.eval;
          };

          # ─── Grafana VMs ──────────────────────────────────────────────────
          # Full demo: Grafana + Prometheus + eval tools
          # Port offset: 200 (SSH: 22222, pmcd: 44521, pmproxy: 44522, Grafana: 13200)
          # Console: serial=24520, virtio=24521
          pcp-microvm-grafana = mkMicroVM {
            variant = "grafana";
            enablePmlogger = false;
            enableEvalTools = true;
            enablePmieTest = true;
            enableGrafana = true;
            enableBpf = true;  # For BPF overview dashboard
            portOffset = constants.variantPortOffsets.grafana;
          };
          pcp-microvm-grafana-tap = mkMicroVM {
            variant = "grafana";
            networking = "tap";
            enablePmlogger = false;
            enableEvalTools = true;
            enablePmieTest = true;
            enableGrafana = true;
            enableBpf = true;  # For BPF overview dashboard
            portOffset = constants.variantPortOffsets.grafana;
          };

          # ─── eBPF VMs ─────────────────────────────────────────────────────
          # BPF: Pre-compiled CO-RE eBPF (fast startup, 1GB)
          # Port offset: 300 (SSH: 22322, pmcd: 44621, pmproxy: 44622)
          # Console: serial=24530, virtio=24531
          pcp-microvm-bpf = mkMicroVM {
            variant = "bpf";
            enablePmlogger = false;
            enableEvalTools = true;
            enablePmieTest = true;
            enableBpf = true;
            portOffset = constants.variantPortOffsets.bpf;
          };

          # NOTE: BCC is deprecated - use BPF PMDA instead (pcp-microvm-bpf)
          # BCC used runtime eBPF compilation which is slower and less reliable
          # than the pre-compiled BPF PMDA CO-RE approach. The BPF PMDA provides
          # the same metrics (runqlat, biolatency, etc.) with better performance.
          #
          # pcp-microvm-bcc = mkMicroVM {
          #   variant = "bcc";
          #   enablePmlogger = false;
          #   enableEvalTools = true;
          #   enablePmieTest = true;
          #   enableBcc = true;
          #   portOffset = constants.variantPortOffsets.bcc;
          # };

          # OCI container image
          pcp-container = import ./nix/container.nix { inherit pkgs pcp; };
        } // (
          # ─── Lifecycle Testing Packages ────────────────────────────────────
          # Import lifecycle testing module and expose its packages
          let
            lifecycle = import ./nix/lifecycle { inherit pkgs lib; };
          in
          lifecycle.packages
        );

        # ─── Apps (Linux only) ───────────────────────────────────────────────
        # VM management scripts work with ALL MicroVM variants via hostname detection.
        # Network scripts for TAP networking setup/teardown.
        # Test scripts for automated MicroVM validation.
        apps = lib.optionalAttrs pkgs.stdenv.isLinux (
          let
            networkScripts = import ./nix/network-setup.nix { inherit pkgs; };
            vmScripts = import ./nix/microvm-scripts.nix { inherit pkgs; };
            mkTest = variant: host: sshPort: description: {
              type = "app";
              program = "${import ./nix/tests/microvm-test.nix {
                inherit pkgs lib variant host sshPort;
              }}/bin/pcp-test-${variant}";
              meta.description = description;
            };
          in {
            # ─── VM Management Scripts ─────────────────────────────────────────
            # These work with ANY MicroVM variant (base, eval, grafana, bpf)
            pcp-vm-check = {
              type = "app";
              program = "${vmScripts.check}/bin/pcp-vm-check";
              meta.description = "List running PCP MicroVMs";
            };
            pcp-vm-stop = {
              type = "app";
              program = "${vmScripts.stop}/bin/pcp-vm-stop";
              meta.description = "Stop all running PCP MicroVMs";
            };
            pcp-vm-ssh = {
              type = "app";
              program = "${vmScripts.ssh}/bin/pcp-vm-ssh";
              meta.description = "SSH into running PCP MicroVM (root:pcp)";
            };
            # Network scripts
            pcp-check-host = {
              type = "app";
              program = "${networkScripts.check}/bin/pcp-check-host";
              meta.description = "Check host requirements for TAP networking";
            };
            pcp-network-setup = {
              type = "app";
              program = "${networkScripts.setup}/bin/pcp-network-setup";
              meta.description = "Create bridge and TAP device for MicroVMs";
            };
            pcp-network-teardown = {
              type = "app";
              program = "${networkScripts.teardown}/bin/pcp-network-teardown";
              meta.description = "Remove bridge and TAP device";
            };
            # MicroVM test scripts (using variant-specific port offsets)
            pcp-test-base-user = mkTest "base-user" "localhost" (constants.ports.sshForward + constants.variantPortOffsets.base) "Test base MicroVM (user networking)";
            pcp-test-base-tap = mkTest "base-tap" constants.network.vmIp 22 "Test base MicroVM (TAP networking)";
            pcp-test-eval-user = mkTest "eval-user" "localhost" (constants.ports.sshForward + constants.variantPortOffsets.eval) "Test eval MicroVM (user networking)";
            pcp-test-eval-tap = mkTest "eval-tap" constants.network.vmIp 22 "Test eval MicroVM (TAP networking)";

            # Comprehensive test runner for all MicroVM variants
            pcp-test-all-microvms = {
              type = "app";
              program = "${import ./nix/tests/test-all-microvms.nix { inherit pkgs lib; }}/bin/pcp-test-all-microvms";
              meta.description = "Run tests on all MicroVM variants";
            };
          } // (
            # ─── Lifecycle Testing Apps ──────────────────────────────────────
            # Import lifecycle testing module and expose its apps
            let
              lifecycle = import ./nix/lifecycle { inherit pkgs lib; };
            in
            lifecycle.apps
          )
        );

        checks = lib.optionalAttrs pkgs.stdenv.isLinux {
          vm-test = import ./nix/vm-test.nix {
            inherit pkgs pcp;
          };
        };

        devShells.default = import ./nix/shell.nix { inherit pkgs pcp; };
      }
    );
}
