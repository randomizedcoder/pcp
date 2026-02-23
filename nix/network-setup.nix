# nix/network-setup.nix
#
# TAP/bridge/vhost-net setup and teardown scripts.
# All network parameters come from constants.nix.
#
# Usage:
#   nix run .#pcp-check-host        # Verify host environment
#   nix run .#pcp-network-setup     # Create bridge + TAP + NAT
#   nix run .#pcp-network-teardown  # Remove bridge + TAP + NAT
#
{ pkgs }:
let
  constants = import ./constants.nix;
  inherit (constants.network) bridge tap subnet gateway vmIp;
in
{
  # Host environment check
  # Verify the host has necessary kernel modules and devices before setup.
  check = pkgs.writeShellApplication {
    name = "pcp-check-host";
    runtimeInputs = with pkgs; [ kmod coreutils ];
    text = ''
      echo "=== PCP MicroVM Host Environment Check ==="
      errors=0

      # Check for TUN device
      if [[ -c /dev/net/tun ]]; then
        echo "OK /dev/net/tun exists"
      else
        echo "FAIL /dev/net/tun not found"
        echo "  Run: sudo modprobe tun"
        errors=$((errors + 1))
      fi

      # Check for vhost-net module/device
      if lsmod | grep -q vhost_net; then
        echo "OK vhost_net module loaded"
      elif [[ -c /dev/vhost-net ]]; then
        echo "OK /dev/vhost-net exists"
      else
        echo "FAIL vhost_net not available"
        echo "  Run: sudo modprobe vhost_net"
        errors=$((errors + 1))
      fi

      # Check for bridge module
      if lsmod | grep -q bridge; then
        echo "OK bridge module loaded"
      else
        echo "INFO bridge module not loaded (will be loaded during setup)"
      fi

      # Check sudo access
      if sudo -n true 2>/dev/null; then
        echo "OK sudo access available"
      else
        echo "FAIL sudo access required for network setup"
        errors=$((errors + 1))
      fi

      if [[ $errors -gt 0 ]]; then
        echo ""
        echo "Host environment check failed with $errors error(s)"
        exit 1
      else
        echo ""
        echo "Host environment ready for TAP networking"
      fi
    '';
  };

  # Network setup
  # Create bridge, TAP device, and NAT rules for VM networking.
  setup = pkgs.writeShellApplication {
    name = "pcp-network-setup";
    runtimeInputs = with pkgs; [ iproute2 kmod nftables acl ];
    text = ''
      echo "=== PCP MicroVM Network Setup ==="

      # Load required kernel modules
      sudo modprobe tun
      sudo modprobe vhost_net
      sudo modprobe bridge

      # Create bridge
      if ! ip link show ${bridge} &>/dev/null; then
        echo "Creating bridge ${bridge}..."
        sudo ip link add ${bridge} type bridge
        sudo ip addr add ${gateway}/24 dev ${bridge}
        sudo ip link set ${bridge} up
      else
        echo "Bridge ${bridge} already exists"
      fi

      # Create TAP device with multi_queue for vhost-net
      if ! ip link show ${tap} &>/dev/null; then
        echo "Creating TAP device ${tap}..."
        sudo ip tuntap add dev ${tap} mode tap multi_queue user "$USER"
        sudo ip link set ${tap} master ${bridge}
        sudo ip link set ${tap} up
      else
        echo "TAP device ${tap} already exists"
      fi

      # Enable vhost-net access (secure method: ACL, fallback: group)
      # SECURITY: We avoid chmod 666 (world-writable) as it's a red flag
      if [[ -c /dev/vhost-net ]]; then
        if command -v setfacl &>/dev/null; then
          # Preferred: ACL-based per-user access
          sudo setfacl -m "u:$USER:rw" /dev/vhost-net
          echo "vhost-net enabled (ACL for $USER)"
        elif getent group kvm &>/dev/null && groups | grep -q kvm; then
          # Fallback: group-based access (user must be in kvm group)
          sudo chgrp kvm /dev/vhost-net
          sudo chmod 660 /dev/vhost-net
          echo "vhost-net enabled (kvm group)"
        else
          echo "WARNING: Cannot set vhost-net permissions securely"
          echo "  Option 1: Install acl package and rerun setup"
          echo "  Option 2: Add $USER to 'kvm' group and rerun setup"
          echo "  vhost acceleration may not work"
        fi
      fi

      # NAT for VM internet access
      echo "Configuring NAT..."
      sudo nft add table inet pcp-nat 2>/dev/null || true
      sudo nft flush table inet pcp-nat 2>/dev/null || true
      sudo nft -f - <<EOF
table inet pcp-nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr ${subnet} masquerade
  }
  chain forward {
    type filter hook forward priority 0;
    iifname "${bridge}" accept
    oifname "${bridge}" ct state related,established accept
  }
}
EOF

      # Enable IP forwarding
      sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

      echo ""
      echo "Network ready. MicroVM will be accessible at:"
      echo "  pmcd:           ${vmIp}:${toString constants.ports.pmcd}"
      echo "  pmproxy:        ${vmIp}:${toString constants.ports.pmproxy}"
      echo "  node_exporter:  ${vmIp}:${toString constants.ports.nodeExporter}"
      echo "  SSH:            ssh root@${vmIp}"
    '';
  };

  # Network teardown
  # Remove bridge, TAP device, and NAT rules.
  teardown = pkgs.writeShellApplication {
    name = "pcp-network-teardown";
    runtimeInputs = with pkgs; [ iproute2 nftables ];
    text = ''
      echo "=== PCP MicroVM Network Teardown ==="

      # Remove TAP device
      if ip link show ${tap} &>/dev/null; then
        sudo ip link del ${tap}
        echo "Removed TAP device ${tap}"
      fi

      # Remove bridge
      if ip link show ${bridge} &>/dev/null; then
        sudo ip link set ${bridge} down
        sudo ip link del ${bridge}
        echo "Removed bridge ${bridge}"
      fi

      # Remove NAT rules
      sudo nft delete table inet pcp-nat 2>/dev/null && \
        echo "Removed NAT rules" || true

      echo "Network teardown complete"
    '';
  };
}
