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
elif [[ "$base" =~ ^[0-9a-f]{40}$ ]] && ! git cat-file -e "$base^{commit}" 2> /dev/null; then
  # A force-push leaves the old tip out of the clone: check what the head adds beyond the default branch.
  git rev-parse --verify --quiet "$head^{commit}" > /dev/null || { echo "Invalid head: $head" >&2; exit 128; }
  if mb=$(git merge-base origin/main "$head" 2> /dev/null); then
    echo "Base $base is not in the repository; fallback: checking commits since the merge base with origin/main ($mb)"
    commits=$(git log --no-merges --format='%h %s' "$mb..$head" --)
  else
    echo "Base $base is not in the repository and origin/main is unavailable; fallback: checking the head commit only"
    commits=$(git log --no-merges --format='%h %s' "$head^!" --)
  fi
else
  commits=$(git log --no-merges --format='%h %s' "$base..$head" --)
fi
pattern='^(feat|fix|test|docs|style|refactor|perf|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .+'
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
