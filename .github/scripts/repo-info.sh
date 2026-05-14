#!/usr/bin/env bash
set -euo pipefail

# Extracts GitHub repo URLs from a PR diff and posts a comment with repo metadata.
# Requires: gh CLI authenticated with GITHUB_TOKEN

PR_NUMBER="${1:?Usage: repo-info.sh <pr-number>}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

# Extract GitHub repo URLs from added lines in the diff
urls=$(gh pr diff "$PR_NUMBER" --repo "$REPO" \
  | grep -E '^\+.*github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+' \
  | grep -oE 'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+' \
  | sed 's:/*$::' \
  | sort -u || true)

if [ -z "$urls" ]; then
  gh pr comment "$PR_NUMBER" --repo "$REPO" --body \
    '📊 **Repository Info** (auto-generated)

No new GitHub repository links detected in this PR.

---
*This comment is auto-generated to help reviewers.*' \
    --edit-last 2>/dev/null || \
  gh pr comment "$PR_NUMBER" --repo "$REPO" --body \
    '📊 **Repository Info** (auto-generated)

No new GitHub repository links detected in this PR.

---
*This comment is auto-generated to help reviewers.*'
  exit 0
fi

comment='📊 **Repository Info** (auto-generated)

'

for url in $urls; do
  owner_repo=$(echo "$url" | sed 's|https://github.com/||')
  owner=$(echo "$owner_repo" | cut -d/ -f1)
  repo_name=$(echo "$owner_repo" | cut -d/ -f2)

  # Fetch repo metadata
  repo_json=$(gh api "repos/$owner_repo" 2>/dev/null || echo "")
  if [ -z "$repo_json" ]; then
    comment+="**[$owner_repo]($url)** — ⚠️ Could not fetch repository info (may not exist or is private)

"
    continue
  fi

  created_at=$(echo "$repo_json" | jq -r '.created_at // empty' | cut -dT -f1)
  pushed_at=$(echo "$repo_json" | jq -r '.pushed_at // empty' | cut -dT -f1)
  stars=$(echo "$repo_json" | jq -r '.stargazers_count // 0')
  license=$(echo "$repo_json" | jq -r '.license.spdx_id // "None detected"')
  archived=$(echo "$repo_json" | jq -r 'if .archived then "⚠️ Yes" else "No" end')
  open_issues=$(echo "$repo_json" | jq -r '.open_issues_count // 0')
  description=$(echo "$repo_json" | jq -r '.description // "No description"' | head -c 200)

  # Fetch contributor count (use Link header to get total)
  contrib_header=$(gh api "repos/$owner_repo/contributors?per_page=1&anon=true" \
    --include 2>/dev/null | head -20 || echo "")
  contrib_count=$(echo "$contrib_header" \
    | grep -i '^link:' \
    | grep -oE 'page=[0-9]+' \
    | tail -1 \
    | cut -d= -f2 || echo "")
  if [ -z "$contrib_count" ]; then
    # No pagination header means 1 page — count items directly
    contrib_count=$(gh api "repos/$owner_repo/contributors?per_page=100&anon=true" \
      --jq 'length' 2>/dev/null || echo "?")
  fi

  # Calculate age
  if [ -n "$created_at" ]; then
    created_ts=$(date -d "$created_at" "+%s" 2>/dev/null || date -jf "%Y-%m-%d" "$created_at" "+%s" 2>/dev/null || echo "")
    now_ts=$(date "+%s")
    if [ -n "$created_ts" ]; then
      age_days=$(( (now_ts - created_ts) / 86400 ))
      if [ "$age_days" -lt 30 ]; then
        age_str="$age_days days ago"
      elif [ "$age_days" -lt 365 ]; then
        age_str="$(( age_days / 30 )) months ago"
      else
        age_str="$(( age_days / 365 )) years ago"
      fi
      created_display="$created_at ($age_str)"
    else
      created_display="$created_at"
    fi
  else
    created_display="Unknown"
  fi

  comment+="| | [$owner_repo]($url) |
|---|---|
| Description | $description |
| Created | $created_display |
| Last push | $pushed_at |
| Stars | $stars |
| Contributors | $contrib_count |
| License | $license |
| Open issues | $open_issues |
| Archived | $archived |

"
done

comment+='---
*This comment is auto-generated to help reviewers. It does not determine whether a tool should be included.*'

# Post or update sticky comment
gh pr comment "$PR_NUMBER" --repo "$REPO" --body "$comment" --edit-last 2>/dev/null || \
  gh pr comment "$PR_NUMBER" --repo "$REPO" --body "$comment"
