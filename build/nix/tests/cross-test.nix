# build/nix/tests/cross-test.nix
#
# Table-driven checks for a cross-compiled PCP package (build/nix/cross.nix).
# One table drives two runners:
#
#   smoke  - flake check: runs the ELF-only rows under qemu-user inside the
#            build sandbox (no hardware, no binfmt needed)
#   app    - nix run .#pcp-cross-test-<arch> -- <ssh-host>
#            copies the package to a real board and runs every row there
#
# Rows compare against the native build of the same source where the output
# is architecture independent (match = "native").
#
{ pkgs, lib, pcpNative, pcpCross, arch }:
let
  helpers = import ../test-common/shell-helpers.nix { };

  # Each row: description, cmd, match, expected, elf.
  #   cmd      bash, with $P = PCP under test, $T = scratch dir, and `run`
  #            prefixed to every PCP executable (qemu-user in the smoke check)
  #   match    exact | regex | min (integer >=) | native (same output as the
  #            native build, store paths normalised)
  #   elf      true if every executable run is an ELF binary, so the row can
  #            run under qemu-user; false for wrapper scripts (pmpython etc.)
  rows = [
    {
      description = "pminfo --version";
      cmd = "run $P/bin/pminfo --version";
      match = "exact";
      expected = "pminfo version ${pcpCross.version}";
      elf = true;
    }
    {
      description = "local linux PMDA exports metrics";
      # stderr dropped: "No PMCD agent for domain" for metrics outside -L
      cmd = "run $P/bin/pminfo -L 2>/dev/null | wc -l";
      match = "min";
      expected = "2000";
      elf = true;
    }
    {
      description = "kernel.uname.machine is the target arch";
      cmd = "run $P/bin/pminfo -L -f kernel.uname.machine";
      match = "regex";
      expected = "value \"${arch}\"";
      elf = true;
    }
    {
      description = "hinv.ncpu is positive";
      cmd = "run $P/bin/pminfo -L -f hinv.ncpu";
      match = "regex";
      expected = "value [1-9]";
      elf = true;
    }
    {
      description = "kernel.all.load metadata matches native";
      cmd = "run $P/bin/pminfo -L -d kernel.all.load";
      match = "native";
      expected = "";
      elf = true;
    }
    {
      description = "kernel.all.load help text matches native";
      cmd = "run $P/bin/pminfo -L -T kernel.all.load";
      match = "native";
      expected = "";
      elf = true;
    }
    {
      description = "negative: unknown metric is reported";
      cmd = "run $P/bin/pminfo -L -f no.such.metric 2>&1";
      match = "regex";
      expected = "Unknown metric name";
      elf = true;
    }
    {
      description = "pmdbg -l debug table matches native";
      cmd = "run $P/bin/pmdbg -l";
      match = "native";
      expected = "";
      elf = true;
    }
    {
      description = "pmieconf rule listing matches native";
      cmd = "run $P/bin/pmieconf -r $P/var/lib/pcp/config/pmieconf -f $T/pmie.conf list all";
      match = "native";
      expected = "";
      elf = true;
    }
    {
      description = "pmcd option parsing matches native";
      cmd = "run $P/libexec/pcp/bin/pmcd --help 2>&1";
      match = "native";
      expected = "";
      elf = true;
    }
    {
      description = "corner: PCP_PYTHON_PROG is the target's python";
      cmd = ". $PCP_DIR/etc/pcp.conf; run \"$PCP_PYTHON_PROG\" -c 'import platform; print(platform.machine())'";
      match = "exact";
      expected = arch;
      elf = true;
    }
    {
      description = "pmpython imports pcp.pmapi";
      cmd = "$P/bin/pmpython -c 'import pcp.pmapi, platform; print(platform.machine())'";
      match = "exact";
      expected = arch;
      elf = false;
    }
    {
      description = "pmiostat (python tool via pmpython) starts";
      cmd = "PATH=$P/bin:$PATH $P/bin/pmiostat --help 2>&1";
      match = "regex";
      expected = "^Usage:";
      elf = false;
    }
  ];

  rowLine = i: r:
    lib.concatMapStringsSep " " lib.escapeShellArg [
      (toString i) r.description r.match r.expected (if r.elf then "1" else "0") r.cmd
    ];

  # Plain bash (run with the target's /bin/bash or the sandbox's), so it is a
  # text file rather than a writeShellScript with a build-machine shebang.
  #   MODE=capture  run the "native" rows with $P = native PCP into $NATIVE_DIR
  #   MODE=check    run all rows with $P = PCP under test, compare
  #   ELF_ONLY=1    skip rows that need wrapper scripts (qemu-user)
  #   RUN           prefix for PCP executables (e.g. qemu-riscv64)
  checks = pkgs.writeText "pcp-cross-checks.sh" ''
    set -u
    export PCP_DIR="$P/share/pcp"
    T=$(mktemp -d)
    run() { ''${RUN:-} "$@"; }
    norm() { sed -e "s|$P|@P@|g"; }
    pass=0 fail=0 skip=0

    row() {
      local i=$1 desc=$2 match=$3 exp=$4 elf=$5 cmd=$6 out ok
      if [ "''${ELF_ONLY:-0}" = 1 ] && [ "$elf" = 0 ]; then
        skip=$((skip + 1)); printf 'SKIP  %s\n' "$desc"; return
      fi
      out=$(eval "$cmd" 2>&1 | norm)
      if [ "$MODE" = capture ]; then
        [ "$match" = native ] && printf '%s\n' "$out" > "$NATIVE_DIR/$i"
        return
      fi
      case $match in
        exact)  [ "$out" = "$exp" ] && ok=1 ;;
        regex)  printf '%s\n' "$out" | grep -Eq -- "$exp" && ok=1 ;;
        min)    [ "$out" -ge "$exp" ] 2>/dev/null && ok=1 ;;
        native) [ "$out" = "$(cat "$NATIVE_DIR/$i" 2>/dev/null)" ] && ok=1 ;;
      esac
      if [ "''${ok:-0}" = 1 ]; then
        pass=$((pass + 1)); printf 'PASS  %s\n' "$desc"
      else
        fail=$((fail + 1)); printf 'FAIL  %s\n' "$desc"
        if [ "$match" = native ]; then
          diff <(cat "$NATIVE_DIR/$i" 2>/dev/null) <(printf '%s\n' "$out") | head -10 | sed 's/^/      /'
        else
          printf '      expected (%s): %s\n      got: %s\n' "$match" "$exp" "$(printf '%s' "$out" | head -5)"
        fi
      fi
    }

    ${lib.concatStringsSep "\n" (lib.imap1 (i: r: "row ${rowLine i r}") rows)}

    rm -rf "$T"
    if [ "$MODE" = check ]; then
      printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
      [ "$fail" = 0 ]
    fi
  '';
in
{
  inherit rows checks;

  # Flake check: ELF rows under qemu-user, no hardware needed.
  smoke = pkgs.runCommand "pcp-cross-smoke-${arch}"
    { nativeBuildInputs = [ pkgs.qemu-user ]; }
    ''
      export NATIVE_DIR=$(mktemp -d)
      P=${pcpNative} MODE=capture bash ${checks}
      rc=0
      P=${pcpCross} MODE=check ELF_ONLY=1 RUN=qemu-${arch} bash ${checks} > $out || rc=$?
      cat $out
      exit $rc
    '';

  # nix run .#pcp-cross-test-<arch> -- <ssh-host>
  app = pkgs.writeShellApplication {
    name = "pcp-cross-test-${arch}";
    runtimeInputs = with pkgs; [ openssh gnutar coreutils gnused ];
    # SC2029: $remote/$host are meant to expand locally in the ssh commands.
    # SC2329: unused functions from the shared colorHelpers.
    excludeShellChecks = [ "SC2029" "SC2329" ];
    text = ''
      ${helpers.colorHelpers}
      host=''${1:?usage: pcp-cross-test-${arch} <ssh-host>   (copies as root@<host>)}
      copy_to=''${COPY_TO:-ssh-ng://root@$host}

      info "Copying ${pcpCross} to $copy_to"
      nix copy --no-check-sigs --to "$copy_to" ${pcpCross}

      # Native results are captured here, then shipped with the checks script
      # (run from a file, not stdin, so commands can't consume the script).
      native=$(mktemp -d)
      trap 'rm -rf "$native"' EXIT
      NATIVE_DIR=$native P=${pcpNative} MODE=capture bash ${checks}
      cp ${checks} "$native/checks.sh"

      remote=/tmp/pcp-cross-test.$$
      info "Running checks on $host"
      tar -C "$native" -cf - . | ssh "$host" "mkdir -p $remote && tar -C $remote -xf -"
      rc=0
      ssh "$host" "NATIVE_DIR=$remote P=${pcpCross} MODE=check bash $remote/checks.sh </dev/null; rc=\$?; rm -rf $remote; exit \$rc" \
        || rc=$?
      exit "$rc"
    '';
  };
}
