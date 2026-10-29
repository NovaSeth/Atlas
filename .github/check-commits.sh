#!/usr/bin/env bash
# Check non-merge commit subjects in BASE..HEAD, or HEAD for a new ref.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 BASE HEAD" >&2
  exit 2
fi
base=$1
head=$2
if [[ -z "$base" || "$base" =~ ^0+$ ]]; then
  commits=$(git log --no-merges --format='%h %s' "$head^!" --)
else
  commits=$(git log --no-merges --format='%h %s' "$base..$head" --)
fi
pattern='^(feat|fix|test|docs|refactor|perf|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .+'
status=0
while IFS= read -r commit; do
  [[ -z "$commit" ]] && continue
  subject=${commit#* }
  if [[ ! "$subject" =~ $pattern ]]; then
    printf 'Non-conventional commit: %s\n' "$commit"
    status=1
  fi
done <<< "$commits"
exit "$status"
