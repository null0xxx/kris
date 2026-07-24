#!/usr/bin/env bash
# verify-env.sh — T1.01 environment assertions (Gate 3 verification, SPEC §25.3/Appendix A).
# Re-runnable host checks: kernel, python, bwrap (+ SPEC §8.1 functional probe),
# userns, ollama, libsecret, git, XDG, uv/pipx status. Exit non-zero on any FAIL.
set -u

fail=0
check() { # check <label> <cmd...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "OK   $label"
  else
    echo "FAIL $label"; fail=1
  fi
}

echo "== lsassist environment verification (T1.01 assertions) =="

# Kernel (expect Linux, userns-capable)
check "kernel present ($(uname -r))" uname -r

# Python >= 3.12
check "python3 >= 3.12 ($(python3 -V 2>&1))" \
  python3 -c 'import sys; assert sys.version_info >= (3, 12)'

# bubblewrap present
check "bwrap present ($(bwrap --version 2>/dev/null))" bwrap --version

# User namespaces enabled
check "userns_clone=1" test "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo 1)" = "1"
check "max_user_namespaces > 0 ($(cat /proc/sys/user/max_user_namespaces 2>/dev/null))" \
  test "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 0)" -gt 0

# bwrap functional probe — SPEC §8.1 profile `ro` binds:
# /usr /bin /lib /lib64 ro-bind, /etc/ld.so.cache + /etc/alternatives ro-bind,
# --unshare-all --die-with-parent --new-session, no network, env allowlist.
bwrap_probe() {
  bwrap \
    --unshare-all --die-with-parent --new-session \
    --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
    --ro-bind /etc/ld.so.cache /etc/ld.so.cache --ro-bind /etc/alternatives /etc/alternatives \
    --proc /proc --dev /dev \
    --tmpfs /tmp \
    --setenv PATH /usr/bin:/bin --setenv HOME /tmp/lsassist-home --setenv LANG C.UTF-8 \
    --chdir /tmp -- /usr/bin/env -i /usr/bin/true
}
check "bwrap functional probe (SPEC §8.1 binds)" bwrap_probe

# Ollama present (local provider)
check "ollama present" ollama --version

# libsecret runtime (D3 keyring)
if ! ldconfig -p 2>/dev/null | grep -q 'libsecret-1\.so\.0'; then
  echo "FAIL libsecret-1.so.0 (ldconfig)"; fail=1
else
  echo "OK   libsecret-1.so.0 (ldconfig)"
fi

# git
check "git present ($(git --version 2>/dev/null))" git --version

# XDG dirs writable
xdg_check() {
  local d="${XDG_DATA_HOME:-$HOME/.local/share}/lsassist"
  mkdir -p "$d" && test -w "$d"
}
check "XDG data dir writable" xdg_check

# uv absent → ADR-005 venv path (informational)
if command -v uv >/dev/null 2>&1; then
  echo "INFO uv present (optional fast-path)"
else
  echo "INFO uv absent — venv path (ADR-005)"
fi

# pipx (informational)
if command -v pipx >/dev/null 2>&1; then
  echo "INFO pipx present"
else
  echo "INFO pipx absent"
fi

if [ "$fail" -ne 0 ]; then
  echo "== RESULT: FAIL =="
  exit 1
fi
echo "== RESULT: OK =="
