# build/nix/fuzz/default.nix
#
# libFuzzer harnesses for libpcp and libpcp_web parsers (manual use only;
# nothing here is in `nix flake check`).
#
#   pcp-fuzz           harnesses + seed corpus + bin/pcp-run-fuzzers
#                        FUZZ_TIME=300 ./result/bin/pcp-run-fuzzers [outdir]
#   pcp-fuzz-run       a bounded run (20 s per harness) as a build:
#                        result/summary.txt, count.txt, crashes/
#   pcp-fuzz-deep      nix run .#pcp-fuzz-deep -- [outdir]
#                        fork mode + dictionaries, FUZZ_DEEP_TIME per harness
#   pcp-fuzz-selftest  fails unless ASan catches the planted overflow
#   pcp-fuzz-cov       llvm-cov line coverage of libpcp from a short run
#
# All runs use one script, run-fuzzers.sh (crash dedup by sanitizer SUMMARY).
# See docs/HowTos/nix/index.rst "Fuzzing".
#
{ pkgs, lib, src }:
let
  sanCFlags = "-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined";

  # instrumented libraries (see libs.nix)
  libs = import ./libs.nix {
    inherit pkgs src;
    fuzzCFlags = "${sanCFlags} -fsanitize=fuzzer-no-link";
  };
  covLibs = import ./libs.nix {
    inherit pkgs src;
    fuzzCFlags = "-g -O1 -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link";
  };

  # harness sources only, so a doc change does not rebuild anything
  fuzzSrc = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [ ./harness ./corpus ./dict ];
  };

  harnesses = [
    "fuzz_pdu"
    "fuzz_hostspec"
    "fuzz_labels"
    "fuzz_derived"
    "fuzz_time"
    "fuzz_units"
    "fuzz_metricspec"
    "fuzz_events"
    "fuzz_loglabel"
    "fuzz_series"
  ];

  symbolizer = "${lib.getBin pkgs.llvm}/bin/llvm-symbolizer";

  # clang command for one harness, against the given libs build
  compile = { l, name, cflags }:
    let
      t = "${l}/tree";
      series = lib.optionalString (name == "fuzz_series") ''
        -I${t}/src/libpcp_web/src \
        -I${t}/vendor/github.com/valkey-io/libvalkey/include \
        -I${t}/vendor/github.com/valkey-io/libvalkey/src \
        ${t}/src/libpcp_web/src/libpcp_web.a ${t}/src/libvalkey/src/libvalkey.a \
        -lpcp_pmda -lpcp_mmv -luv -lssl -lcrypto -lsasl2 -linih -lm \
      '';
    in ''
      clang ${cflags} \
        -DFUZZ_PCP_CONF='"${t}/src/include/pcp.conf"' \
        -DFUZZ_SYMBOLIZER='"${symbolizer}"' \
        -I${t}/src/include -I${t}/src/include/pcp -Iharness \
        harness/${name}.c \
        ${series} -L${l}/lib -lpcp -Wl,-rpath,${l}/lib \
        -o out/bin/${name}
    '';

  # one derivation with every harness built against `l`
  mkHarnesses = { pname, l, cflags }: pkgs.clangStdenv.mkDerivation {
    inherit pname;
    version = "0";
    src = fuzzSrc;
    buildInputs = with pkgs; [ libuv openssl cyrus_sasl inih ];
    hardeningDisable = [ "all" ];
    dontConfigure = true;
    dontFixup = true;
    buildPhase = ''
      runHook preBuild
      mkdir -p out/bin out/corpus out/dict
      ${lib.concatMapStrings (name: compile { inherit l name cflags; }) harnesses}
      clang ${cflags} harness/fuzz_selftest.c -o out/bin/fuzz_selftest
      cp -r corpus/. out/corpus/
      cp -r dict/. out/dict/
      runHook postBuild
    '';
    installPhase = ''cp -r out "$out"'';
  };

  linkFlags = "${sanCFlags} -fsanitize=fuzzer";

  harnessBins = mkHarnesses {
    pname = "pcp-fuzz-harnesses";
    l = libs;
    cflags = linkFlags;
  };

  # pcp-fuzz-runner <bindir> <corpus> [outdir]
  runner = pkgs.writeShellApplication {
    name = "pcp-fuzz-runner";
    runtimeInputs = with pkgs; [ coreutils findutils gnugrep gnused ];
    runtimeEnv.ASAN_SYMBOLIZER_PATH = symbolizer;
    text = builtins.readFile ./run-fuzzers.sh;
  };

  runFuzzers = pkgs.writeShellApplication {
    name = "pcp-run-fuzzers";
    text = ''
      export FUZZ_DICTDIR=''${FUZZ_DICTDIR:-${harnessBins}/dict}
      exec ${lib.getExe runner} ${harnessBins}/bin ${harnessBins}/corpus "$@"
    '';
  };

  pcp-fuzz = pkgs.symlinkJoin {
    name = "pcp-fuzz";
    paths = [ harnessBins runFuzzers ];
  };

  pcp-fuzz-run = pkgs.runCommand "pcp-fuzz-run" { } ''
    FUZZ_TIME=20 ${lib.getExe runFuzzers} "$out"
  '';

  # A command, not a build, so the time can be set when it runs.
  pcp-fuzz-deep = pkgs.writeShellApplication {
    name = "pcp-fuzz-deep";
    text = ''
      # pcp-fuzz-deep [outdir]: FUZZ_DEEP_TIME (600 s per harness),
      # FUZZ_DEEP_FORKS (nproc), FUZZ_DEEP_MAXLEN (65536).
      export FUZZ_TIME=''${FUZZ_DEEP_TIME:-600}
      export FUZZ_FORKS=''${FUZZ_DEEP_FORKS:-$(nproc)}
      export FUZZ_MAXLEN=''${FUZZ_DEEP_MAXLEN:-65536}
      exec ${lib.getExe runFuzzers} "''${1:-pcp-fuzz-deep-out}"
    '';
  };

  # Gate: the planted overflow must be found, else the sanitizer or
  # harness build is broken and other results mean nothing.
  pcp-fuzz-selftest = pkgs.runCommand "pcp-fuzz-selftest" { } ''
    mkdir -p $out
    printf 'PC%062d' 0 > input
    if ${harnessBins}/bin/fuzz_selftest input > $out/selftest.log 2>&1; then
      echo "FAIL: fuzz_selftest did not report the overflow" | tee $out/verdict.txt
      exit 1
    fi
    if ! grep -q 'AddressSanitizer: heap-buffer-overflow' $out/selftest.log; then
      echo "FAIL: no ASan heap-buffer-overflow report" | tee $out/verdict.txt
      exit 1
    fi
    echo "PASS: ASan found the planted overflow" | tee $out/verdict.txt
  '';

  covBins = mkHarnesses {
    pname = "pcp-fuzz-cov-harnesses";
    l = covLibs;
    cflags = "-g -O1 -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer";
  };

  # Short run of each harness with coverage on, then one llvm-cov report
  # for libpcp.so (+ the series parser objects in fuzz_series).
  pcp-fuzz-cov = pkgs.runCommand "pcp-fuzz-cov"
    { nativeBuildInputs = [ pkgs.llvm ]; } ''
    mkdir -p $out work
    export PCP_DERIVED_CONFIG=
    t=''${FUZZ_COV_TIME:-20}
    for name in ${lib.concatStringsSep " " harnesses}; do
      mkdir -p work/$name
      cp -r ${covBins}/corpus/$name/. work/$name/ 2>/dev/null || true
      chmod -R u+w work/$name
      # Fork mode keeps going after a crash (a crashed process writes no
      # profile); each child writes its own profile (%p).  There is no
      # ASan here, so a heap overflow can leave malloc broken and a crash
      # handler would then hang: the handlers are off, a crashing child
      # just dies.  The hard timeout is a last guard.
      UBSAN_OPTIONS=handle_segv=0:handle_abort=0:handle_sigbus=0:handle_sigfpe=0:handle_sigill=0 \
      LLVM_PROFILE_FILE="work/$name-%p.profraw" \
        timeout -s KILL $((t + 60)) \
        ${covBins}/bin/$name -fork=1 -ignore_crashes=1 -ignore_timeouts=1 \
        -ignore_ooms=1 -timeout=5 -handle_segv=0 -handle_abrt=0 \
        -handle_bus=0 -handle_ill=0 -handle_fpe=0 -max_total_time=$t \
        work/$name > work/$name.log 2>&1 || true
    done
    llvm-profdata merge -sparse work/*.profraw -o $out/pcp.profdata
    objs=""
    for name in ${lib.concatStringsSep " " harnesses}; do
      objs="$objs -object ${covBins}/bin/$name"
    done
    llvm-cov report ${covLibs}/lib/libpcp.so $objs \
      -instr-profile=$out/pcp.profdata \
      -ignore-filename-regex='(harness/|/nix/store/[^/]*-(glibc|libuv|openssl))' \
      > $out/summary.txt
    tail -n 1 $out/summary.txt
  '';
in
{
  packages = {
    inherit pcp-fuzz pcp-fuzz-run pcp-fuzz-deep pcp-fuzz-selftest pcp-fuzz-cov;
    pcp-fuzz-libs = libs;
  };
  apps = {
    pcp-fuzz-deep = {
      type = "app";
      program = lib.getExe pcp-fuzz-deep;
    };
  };
}
