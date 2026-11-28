# build/nix/analysis/default.nix
#
# Static analysis of the PCP sources (manual use only; nothing here is
# in `nix flake check`).  The tools report; they do not fail on findings.
# A build fails only when the tool setup itself is broken.
#
#   pcp-analysis-quick      cppcheck, flawfinder, shellcheck, ruff, bandit
#   pcp-analysis-standard   + clang-tidy, semgrep, coccinelle
#   pcp-analysis-deep       + scan-build, gcc -fanalyzer, gcc extra warnings
#   pcp-analysis-all        deep + a pcp-fuzz-run, in one triage
#   pcp-analysis-triage     (app) the triage report on a result, by hand
#
# Each tool is also a package: pcp-analysis-<tool>.  Output:
#   result/report.txt   one finding per line (file:line:col: ...)
#   result/count.txt    number of findings
# A tier has one directory per tool, summary.txt, and triage/ (ranked
# findings: high-confidence.txt, cross-ref.txt, summary.txt, ...).
#
# Findings in vendor/, src/external/, deps/, qa/ and generated
# parser/lexer files are left out.  Known findings are kept in
# anomalies.toml.  See docs/HowTos/nix/index.rst "Static Analysis".
#
{ pkgs, lib, src, fuzzRun ? null }:
let
  # PCP as `nix build .#pcp` builds it, with the given stdenv; the bpf
  # PMDAs are off (they build vendored libbpf/bpftool, not PCP code).
  pcpWith = stdenv:
    (import ../package.nix {
      pkgs = pkgs // { inherit stdenv; };
      inherit src;
    }).overrideAttrs (old: {
      configureFlags = map (f:
        if f == "--with-pmdabpf=yes" then "--with-pmdabpf=no"
        else if f == "--with-pmdabpftrace=yes" then "--with-pmdabpftrace=no"
        else f) old.configureFlags;
    });

  # Paths that are not PCP's own code, or not product code.
  excludeRegex = "(^|/)(vendor|src/external|deps|qa)/|\\.tab\\.[ch]|lex\\.yy\\.c|/lex\\.[a-z_]*\\.c";
  # the same regex inside a jq string literal
  jqExcludeRegex = lib.replaceStrings [ "\\" ] [ "\\\\" ] excludeRegex;

  jobs = "$NIX_BUILD_CORES";
  python = "${pkgs.python3}/bin/python3";

  # A finding line: path:line:col: ...
  findingRegex = "^[^:]+:[0-9]+:[0-9]+: ";

  # The source tree as package.nix sees it.  The source only tools run
  # on a copy of it, so report paths are relative to the repo root.
  pcpSrc = (pcpWith pkgs.stdenv).src;

  # Shell snippets that write file lists, relative to the source root.
  listC = ''
    find src -name '*.[ch]' | grep -vE '${excludeRegex}' | sort > files-c.txt
  '';
  listShell = ''
    find src build scripts -type f ! -name '*.[ch]' -size -512k \
      | grep -vE '${excludeRegex}' | sort | while read -r f; do
        case "$f" in
        *.sh) echo "$f" ;;
        *) head -n 1 "$f" | grep -qE '^#! *(/usr)?/bin/(env +)?(ba)?sh( |$)' && echo "$f" ;;
        esac
      done > files-sh.txt || true
  '';
  listPython = ''
    find src build -type f -size -512k \
      | grep -vE '${excludeRegex}' | sort | while read -r f; do
        case "$f" in
        *.py|*.python) echo "$f" ;;
        *) head -n 1 "$f" | grep -qE '^#!.*python' && echo "$f" ;;
        esac
      done > files-py.txt || true
  '';

  # A tool that only reads the source (no configure, no build).
  # `analyze` runs in a copy of the source and writes $out/report.txt.
  mkSourceTool = { name, tools ? [ ], analyze, count ? findingRegex }:
    pkgs.runCommand "pcp-analysis-${name}"
      { nativeBuildInputs = tools ++ (with pkgs; [ coreutils findutils gnugrep gnused ]); }
      ''
        mkdir -p $out
        cp -r ${pcpSrc} source && chmod -R u+w source && cd source
        ${analyze}
        grep -vE '${excludeRegex}' $out/report.txt > report.tmp || true
        mv report.tmp $out/report.txt
        n=$(grep -cE '${count}' $out/report.txt || true)
        echo "''${n:-0}" > $out/count.txt
        echo "${name}: ''${n:-0} finding(s)"
      '';

  # A tool that needs a PCP build tree after configure.  `analyze` runs
  # instead of the build and must write $out/report.txt.
  mkTool = { name, stdenv ? pkgs.stdenv, tools ? [ ], analyze, count ? findingRegex }:
    (pcpWith stdenv).overrideAttrs (old: {
      pname = "pcp-analysis-${name}";
      outputs = [ "out" ];
      nativeBuildInputs = old.nativeBuildInputs ++ tools ++ [ pkgs.gnugrep ];
      buildPhase = ''
        runHook preBuild
        mkdir -p $out
        ${analyze}
        runHook postBuild
      '';
      installPhase = ''
        grep -vE '${excludeRegex}' $out/report.txt > report.tmp || true
        mv report.tmp $out/report.txt
        n=$(grep -cE '${count}' $out/report.txt || true)
        echo "''${n:-0}" > $out/count.txt
        echo "${name}: ''${n:-0} finding(s)"
      '';
      postInstall = "";
      postFixup = "";
      dontFixup = true;
      doInstallCheck = false;
      separateDebugInfo = false;
    });

  # Writes ./ccwrap, a CC for `make CC=$PWD/ccwrap` (see ccwrap.py).
  mkCcWrap = ''
    export CCWRAP_CC=$(command -v $CC)
    printf '#!%s\nexec %s -B %s "$@"\n' ${pkgs.runtimeShell} ${python} ${./ccwrap.py} > ccwrap
    chmod +x ccwrap
  '';

  # A full `make -k` with extra compiler flags.  The warnings whose
  # [flag] matches `flagRegex` are the report, with repo relative paths
  # (ccwrap.py makes the paths absolute, diagpaths.py makes them repo
  # relative).  make -O keeps each target's output together.
  mkCompilerTool = { name, cflags, flagRegex }: mkTool {
    inherit name;
    analyze = ''
      export NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE ${cflags}"
      ${mkCcWrap}
      CCWRAP_ABSPATH=1 make -k -j${jobs} -O -w CC=$PWD/ccwrap > build.log 2>&1 || true
      ${python} ${./diagpaths.py} build.log "$PWD" '${flagRegex}' > $out/report.txt
    '';
  };

  # --- tools that read the source ---

  cppcheck = mkTool {
    name = "cppcheck";
    tools = [ pkgs.cppcheck pkgs.findutils ];
    # generated headers (config.h, pmdbg.h, ...) are needed first.
    # System headers are not read, so the limits that platform_defs.h
    # needs from them are given with -D.
    analyze = ''
      make -C src/include
      find src -name '*.c' | grep -vE '${excludeRegex}' | sort > files.txt
      cppcheck -j${jobs} --quiet --std=c11 --platform=unix64 \
        --enable=warning,performance,portability --max-configs=1 \
        --inline-suppr --suppress=missingInclude --suppress=missingIncludeSystem \
        --suppress=unknownMacro --suppress=normalCheckLevelMaxBranches \
        -Isrc/include -Isrc/include/pcp -D__linux__ \
        -DFILENAME_MAX=4096 -DMAXPATHLEN=4096 -DMAXHOSTNAMELEN=256 \
        --template='{file}:{line}:{column}: {severity}: {message} [{id}]' \
        --file-list=files.txt 2> $out/report.txt || true
      cp files.txt $out/files.txt
    '';
  };

  # CWE tagged risky calls; quick, no build.
  flawfinder = mkSourceTool {
    name = "flawfinder";
    tools = [ pkgs.flawfinder ];
    analyze = ''
      ${listC}
      xargs flawfinder --minlevel=1 --columns --singleline --dataonly --quiet \
        < files-c.txt > $out/report.txt 2> $out/stderr.log || true
    '';
  };

  shellcheck = mkSourceTool {
    name = "shellcheck";
    tools = [ pkgs.shellcheck ];
    analyze = ''
      ${listShell}
      cp files-sh.txt $out/files.txt
      xargs -n 50 shellcheck -f gcc < files-sh.txt > $out/report.txt 2>&1 || true
    '';
  };

  # Python: pyflakes errors, syntax errors and bugbear, not style.
  ruff = mkSourceTool {
    name = "ruff";
    tools = [ pkgs.ruff ];
    analyze = ''
      ${listPython}
      cp files-py.txt $out/files.txt
      xargs ruff check --isolated --no-cache --output-format=concise \
        --select=F,E9,B,PLE < files-py.txt > $out/report.txt 2>&1 || true
    '';
  };

  bandit = mkSourceTool {
    name = "bandit";
    tools = [ pkgs.bandit ];
    analyze = ''
      ${listPython}
      xargs bandit -q -f custom \
        --msg-template '{relpath}:{line}:{col}: warning: [{severity}] {msg} [{test_id}]' \
        < files-py.txt > $out/report.txt 2> $out/stderr.log || true
    '';
  };

  # Vendored C rules (rules/semgrep-c.yaml).
  semgrep = mkSourceTool {
    name = "semgrep";
    tools = [ pkgs.semgrep ];
    analyze = ''
      # semgrep loads a CA bundle at start even offline (no network is used)
      export HOME=$TMPDIR SEMGREP_SEND_METRICS=off OTEL_TRACES_EXPORTER=none
      export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
      semgrep scan --metrics=off --disable-version-check --no-git-ignore \
        --config ${./rules/semgrep-c.yaml} --json -j ${jobs} \
        --include='*.c' --include='*.h' \
        --exclude=vendor --exclude=external --exclude=deps \
        src > $out/report.json 2> $out/stderr.log || true
      if [ ! -s $out/report.json ]; then
        echo "semgrep: no JSON output" >&2
        tail -40 $out/stderr.log >&2
        exit 1
      fi
      ${python} - $out/report.json > $out/report.txt <<'EOF'
      import json, sys
      for r in json.load(open(sys.argv[1])).get("results", []):
          print("%s:%d:%d: %s: %s [semgrep.%s]" % (
              r["path"], r["start"]["line"], r["start"]["col"],
              r["extra"]["severity"].lower(), r["extra"]["message"],
              r["check_id"].rsplit(".", 1)[-1]))
      EOF
    '';
  };

  # Vendored semantic patches (rules/coccinelle/*.cocci); each prints
  # file:line:col: warning: ... [cocci.<rule>].
  coccinelle = mkSourceTool {
    name = "coccinelle";
    tools = [ pkgs.coccinelle pkgs.python3 ];
    analyze = ''
      : > report.txt
      for rule in ${./rules/coccinelle}/*.cocci; do
        spatch --sp-file "$rule" --dir src -j ${jobs} --very-quiet \
          --no-includes --timeout 120 >> report.txt 2>> $out/stderr.log || true
      done
      grep -E '\[cocci\.' report.txt | sort -u > $out/report.txt || true
    '';
  };

  # --- tools that build PCP ---

  # Full build with ccwrap.py as CC to record compile_commands.json (bear
  # cannot see through the nix cc-wrapper), then clang-tidy on every PCP
  # C file in it.  The compile db is kept in the output.
  clang-tidy = mkTool {
    name = "clang-tidy";
    stdenv = pkgs.clangStdenv;
    tools = [ pkgs.clang-tools pkgs.jq pkgs.python3 ];
    analyze = ''
      ${mkCcWrap}
      export CCWRAP_CDB=$PWD/cdb.jsonl
      : > $CCWRAP_CDB
      CCWRAP_ABSPATH=1 make -k -j${jobs} CC=$PWD/ccwrap > build.log 2>&1 || true
      jq -s . $CCWRAP_CDB > compile_commands.json
      jq '[.[] | select(.file | test("${jqExcludeRegex}") | not)
               | select(.file | endswith(".c"))]' \
        compile_commands.json > cdb.json
      mkdir -p cdb && mv cdb.json cdb/compile_commands.json
      if [ "$(jq length cdb/compile_commands.json)" -eq 0 ]; then
        echo "clang-tidy: empty compile database" >&2
        tail -50 build.log >&2
        exit 1
      fi
      # left out: PCP idioms (assignment in if, atoi, unused PMDA
      # callback args, implicit void * casts) and "use the C11 _s
      # functions" (every printf), which would bury the rest
      checks='-*,bugprone-*,cert-*,clang-analyzer-*,misc-*'
      for c in misc-include-cleaner misc-unused-parameters misc-no-recursion \
          misc-header-include-cycle bugprone-easily-swappable-parameters \
          bugprone-reserved-identifier bugprone-assignment-in-if-condition \
          bugprone-narrowing-conversions bugprone-switch-missing-default-case \
          bugprone-multi-level-implicit-pointer-conversion \
          bugprone-macro-parentheses cert-dcl37-c cert-dcl51-cpp cert-err33-c \
          cert-err34-c \
          clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling; do
        checks="$checks,-$c"
      done
      # run-clang-tidy is only in the unwrapped clang, with a
      # "#! /usr/bin/env python3" line, so run it with python3
      ${python} ${pkgs.llvmPackages.clang-unwrapped}/bin/run-clang-tidy -p cdb -j ${jobs} -quiet \
        -clang-tidy-binary ${pkgs.clang-tools}/bin/clang-tidy \
        -checks="$checks" \
        -extra-arg=-Wno-unknown-warning-option \
        > tidy.log 2>&1 || true
      # diagnostic lines in the tree only (not source snippets or
      # /nix/store headers), with repo paths
      ${python} ${./diagpaths.py} tidy.log "$PWD" '.' > $out/report.txt
      cp tidy.log $out/tidy.log
      if [ ! -s $out/report.txt ]; then
        echo "clang-tidy: no findings, the end of tidy.log:" >&2
        tail -40 tidy.log >&2
      fi
      cp compile_commands.json $out/
    '';
  };

  # clang static analyzer over the whole make.  configure runs under
  # scan-build too (below), so CC is ccc-analyzer for the build.  This is
  # the wrapped scan-build: the one in clang has a /usr/bin/env #! line.
  scanBuildBin = "${pkgs.clang-analyzer}/bin/scan-build";
  scan-build-tool = mkTool {
    name = "scan-build";
    stdenv = pkgs.clangStdenv;
    tools = [ pkgs.clang-analyzer pkgs.findutils pkgs.gnused ];
    analyze = ''
      ${scanBuildBin} -o $out/html --keep-going \
        make -k -j${jobs} > build.log 2>&1 || true
      tail -3 build.log
      find $out/html -name 'report-*.html' | sort | while read -r r; do
        tag() { sed -n "s/^<!-- $1 \(.*\) -->$/\1/p" "$r"; }
        slug=$(tag BUGTYPE | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '-' | sed 's/-$//')
        echo "$(tag BUGFILE | sed 's|^/build/source/||'):$(tag BUGLINE):$(tag BUGCOLUMN): warning: $(tag BUGDESC) ($(basename "$r")) [scan-build.$slug]"
      done | sort -u > $out/report.txt
    '';
  };
  scan-build = scan-build-tool.overrideAttrs (old: {
    configurePhase = ''
      runHook preConfigure
      ${scanBuildBin} -o $TMPDIR/configure-reports ./configure $configureFlags
      runHook postConfigure
    '';
  });

  # gcc's own path-sensitive analyzer, over the whole make.  Slowest.
  gcc-analyzer = mkCompilerTool {
    name = "gcc-analyzer";
    cflags = "-fanalyzer";
    flagRegex = "^-Wanalyzer-";
  };

  # Extra gcc warnings that find bugs, not style.  -Wconversion,
  # -Wsign-conversion and -Wpedantic are left out: they give tens of
  # thousands of findings.
  gccWarningFlags = [
    "-Wall" "-Wextra" "-Wformat=2" "-Wformat-overflow=2"
    "-Wformat-truncation=2" "-Wformat-signedness" "-Wshadow" "-Wcast-qual"
    "-Wcast-align=strict" "-Wwrite-strings" "-Wpointer-arith"
    "-Wduplicated-cond" "-Wduplicated-branches" "-Wlogical-op"
    "-Wnull-dereference" "-Wfloat-equal" "-Walloca" "-Wvla"
    "-Wstrict-prototypes" "-Wold-style-definition" "-Wjump-misses-init"
    "-Wstringop-overflow=4" "-Warray-bounds=2" "-Wuse-after-free=3"
  ];
  gcc-warnings = mkCompilerTool {
    name = "gcc-warnings";
    cflags = lib.concatStringsSep " " gccWarningFlags;
    flagRegex = "^-W";
  };

  tools = {
    inherit cppcheck flawfinder shellcheck ruff bandit
      clang-tidy semgrep coccinelle
      scan-build gcc-analyzer gcc-warnings;
  };

  # --- triage (python, ported from rocm-systems nix/analysis/triage) ---

  triageSrc = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [ ./triage ./anomalies.toml ./diagpaths.py ./ccwrap.py ];
  };
  triageMain = "${triageSrc}/triage/__main__.py";

  # A tier: a link to each tool's output, summary.txt, and triage/.
  mkTier = tier: names: extra: pkgs.runCommand "pcp-analysis-${tier}" { } ''
    mkdir -p $out
    total=0
    {
      echo "=== PCP static analysis: ${tier} ==="
      ${lib.concatMapStrings (n: ''
        ln -s ${tools.${n}} $out/${n}
        c=$(cat ${tools.${n}}/count.txt)
        total=$((total + c))
        printf '  %-14s %s finding(s)\n' "${n}" "$c"
      '') names}
      ${extra}
      echo
      echo "Total: $total"
    } | tee $out/summary.txt
    echo "$total" > $out/count.txt
    ${python} -B ${triageMain} --source-root ${pcpSrc} \
      --anomalies-file ${triageSrc}/anomalies.toml \
      --output-dir $out/triage $out
    echo "High-confidence: $(cat $out/triage/count.txt) (result/triage/high-confidence.txt)" \
      | tee -a $out/summary.txt
  '';

  quick = [ "cppcheck" "flawfinder" "shellcheck" "ruff" "bandit" ];
  standard = quick ++ [ "clang-tidy" "semgrep" "coccinelle" ];
  deep = standard ++ [ "scan-build" "gcc-analyzer" "gcc-warnings" ];

  # pcp-analysis-triage <result dir> [triage options]; run in the repo
  # root, so code anchors are read from (and anomalies.toml edits are
  # taken from) the working tree.
  triageApp = pkgs.writeShellApplication {
    name = "pcp-analysis-triage";
    text = ''
      anomalies=${triageSrc}/anomalies.toml
      if [ -f build/nix/analysis/anomalies.toml ]; then
        anomalies=build/nix/analysis/anomalies.toml
      fi
      exec ${python} -B ${triageMain} --source-root . --anomalies-file "$anomalies" "$@"
    '';
  };

  # Table driven unit tests of the triage parsers and matching.
  triageTest = pkgs.runCommand "pcp-analysis-triage-test" { } ''
    cd ${triageSrc}/triage
    ${python} -B -m unittest -v test_triage 2>&1 | tee $out
  '';
in
{
  packages = lib.mapAttrs' (n: v: lib.nameValuePair "pcp-analysis-${n}" v) tools // {
    pcp-analysis-quick = mkTier "quick" quick "";
    pcp-analysis-standard = mkTier "standard" standard "";
    pcp-analysis-deep = mkTier "deep" deep "";
    pcp-analysis-triage = triageApp;
    pcp-analysis-triage-test = triageTest;
  } // lib.optionalAttrs (fuzzRun != null) {
    # deep + the fuzzer crashes, which are findings for triage too
    pcp-analysis-all = mkTier "all" deep ''
      ln -s ${fuzzRun} $out/fuzz-run
      c=$(cat ${fuzzRun}/distinct_count.txt)
      total=$((total + c))
      printf '  %-14s %s distinct crash(es)\n' fuzz-run "$c"
    '';
  };
  apps.pcp-analysis-triage = {
    type = "app";
    program = lib.getExe triageApp;
  };
}
