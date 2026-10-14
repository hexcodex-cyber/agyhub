#!/bin/sh
# Gate before any push. Exits 0 only when this tree is safe to publish.
set -eu
cd "$(dirname "$0")/.."

bad=$(git ls-files 2>/dev/null | grep -E '(^|/)(secrets\.json|\.password|\.totp-once|auth\.json)$|\.token$' || true)
if [ -n "$bad" ]; then
  echo "NOT READY: secret files are tracked"
  printf '%s\n' "$bad"
  exit 1
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git grep -I -n -E 'ghp_[A-Za-z0-9]|github_pat_|BEGIN (OPENSSH|RSA|EC) PRIVATE KEY|AGYHUB_PASSWORD=.+' -- . ':!deploy/ready.sh'; then
    echo "NOT READY: secret-shaped line in a tracked file"
    exit 1
  fi
fi

url=$(git remote get-url origin 2>/dev/null || true)
if [ -n "$url" ]; then
  case "$url" in
    *@*)
      echo "NOT READY: origin URL contains credentials"
      exit 1
      ;;
  esac
fi

echo "READY origin=${url:-unset}"
