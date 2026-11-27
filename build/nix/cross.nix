# build/nix/cross.nix
#
# Cross-compiled PCP for another 64-bit Linux architecture, built on this
# machine with nixpkgs' cross toolchains (no emulation, no native builds on
# the target board).  The cross-specific handling lives in package.nix behind
# `isCross`; this file only sets up the cross package set.
#
#   nix build .#pcp-riscv64      # or .#pcp-aarch64
#   nix copy --no-check-sigs --to ssh-ng://root@<board> ./result
#
{ nixpkgs, system, src, crossSystem }:
let
  inherit (nixpkgs) lib;
  pkgsCross = import nixpkgs {
    localSystem = system;
    inherit crossSystem;
    overlays = [
      # nixpkgs' rrdtool does not cross-compile (drop once fixed in nixpkgs):
      #  - m4/acinclude.m4 uses AC_CHECK_PROGS(PKGCONFIG,[pkg-config]), which
      #    misses the target-prefixed pkg-config wrapper
      #  - configure needs nroff, and autoreconf needs perl (NUMVERS), on the
      #    build machine; both are only in buildInputs
      #  - the language bindings can't be cross-built, and postInstall moves
      #    the perl ones; PCP only optionally uses perl RRDs
      # Only for packages built for the target: buildPackages (and so the
      # build-machine PCP in package.nix) keep the stock rrdtool.
      (final: prev: lib.optionalAttrs (!prev.stdenv.buildPlatform.canExecute prev.stdenv.hostPlatform) {
        rrdtool = prev.rrdtool.overrideAttrs (old: {
          PKGCONFIG = "${final.stdenv.cc.targetPrefix}pkg-config";
          nativeBuildInputs = old.nativeBuildInputs ++ [
            final.buildPackages.groff
            final.buildPackages.perl
          ];
          configureFlags = (old.configureFlags or [ ]) ++ [
            "--disable-perl"
            "--disable-python"
            "--disable-ruby"
            "--disable-lua"
            "--disable-tcl"
          ];
          postInstall = "";
        });
      })
    ];
  };
in
import ./package.nix { pkgs = pkgsCross; inherit src; }
