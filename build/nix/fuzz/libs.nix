# build/nix/fuzz/libs.nix
#
# libpcp and libpcp_web built with clang for libFuzzer:
#   -fsanitize=fuzzer-no-link,address,undefined
#
# Only the libraries the harnesses need are built (src/include, src/libpcp,
# src/libpcp_pmda, src/libpcp_mmv, src/libvalkey, src/libpcp_web).
#
# Output:
#   $out/lib/       libpcp.so*, libpcp_web.so*
#   $out/tree/      the built source tree for these dirs (headers, *.o, *.a)
#
# The sanitizer runtime is linked into each harness, not into the .so files,
# so "-Wl,--no-undefined" is removed from builddefs for this build only.
#
{ pkgs, src, fuzzCFlags }:
let
  lib = pkgs.lib;

  # Same PCP derivation as `nix build .#pcp`, but with the clang stdenv.
  pcpClang = import ../package.nix {
    pkgs = pkgs // { stdenv = pkgs.clangStdenv; };
    inherit src;
  };
in
pcpClang.overrideAttrs (old: {
  pname = "pcp-fuzz-libs";
  outputs = [ "out" ];

  postPatch = (old.postPatch or "") + ''
    substituteInPlace src/include/builddefs.in \
      --replace-fail "LDFLAGS += -Wl,--no-undefined" ""
    # check-statics does not know the symbols clang's ASan/sancov add.
    substituteInPlace src/libpcp/src/GNUmakefile \
      --replace-fail "./check-statics" "true ./check-statics"
  '';

  # Instrument only what make compiles, not the configure tests.
  preBuild = ''
    export NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE ${fuzzCFlags}"
    export ASAN_OPTIONS=detect_leaks=0
  '';

  buildPhase = ''
    runHook preBuild
    for d in src/include src/libpcp src/libpcp_pmda src/libpcp_mmv src/libvalkey src/libpcp_web; do
      make -j"$NIX_BUILD_CORES" -C "$d"
    done
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib $out/tree/src $out/tree/vendor/github.com
    cp -P src/libpcp/src/libpcp.so* src/libpcp_pmda/src/libpcp_pmda.so* \
      src/libpcp_mmv/src/libpcp_mmv.so* src/libpcp_web/src/libpcp_web.so* $out/lib/
    cp -r src/include src/libpcp src/libvalkey src/libpcp_web $out/tree/src/
    cp -r vendor/github.com/valkey-io $out/tree/vendor/github.com/
    runHook postInstall
  '';

  postInstall = "";
  postFixup = "";
  dontFixup = true;
  doInstallCheck = false;
  separateDebugInfo = false;
  hardeningDisable = [ "all" ];
})
