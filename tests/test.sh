#!/usr/bin/env bash
set -euo pipefail

EVC="${EVC:-eosvc}"
ORG="${ORG:-ersilia-os}"
BRANCH="${BRANCH:-main}"

run() {
  echo
  echo "==> $*"
  "$@"
}

run_may_fail() {
  echo
  echo "==> $* (allowed to fail)"
  set +e
  "$@"
  local rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    echo "WARN: command failed (exit=$rc) but continuing: $*"
  fi
  return 0
}

header() {
  echo
  echo "############################################################"
  echo "# $*"
  echo "############################################################"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }
}

ensure_clean_dir() {
  local d="$1"
  if [ -e "$d" ]; then
    echo "Removing existing directory: $d"
    rm -rf "$d"
  fi
}

git_clone_repo() {
  local repo="$1"
  local dest="$2"
  local url="https://github.com/${ORG}/${repo}.git"
  ensure_clean_dir "$dest"
  run git clone --branch "$BRANCH" --single-branch "$url" "$dest"
}

write_access_json_model() {
  local repo_dir="$1"
  cat > "${repo_dir}/access.json" <<'JSON'
{
  "checkpoints": "public",
  "fit": "public"
}
JSON
}

write_access_json_standard() {
  local repo_dir="$1"
  cat > "${repo_dir}/access.json" <<'JSON'
{
  "data": "public",
  "output": "public"
}
JSON
}

make_dummy_files_model() {
  local repo_dir="$1"
  mkdir -p "${repo_dir}/model/checkpoints/test-run"
  mkdir -p "${repo_dir}/model/fit/fit/test-fit"
  echo "checkpoint blob" > "${repo_dir}/model/checkpoints/test-run/ckpt.txt"
  echo "fit blob" > "${repo_dir}/model/fit/fit/test-fit/fw.txt"
}

make_dummy_files_standard() {
  local repo_dir="$1"
  mkdir -p "${repo_dir}/data/test"
  mkdir -p "${repo_dir}/output/test"
  echo "data blob" > "${repo_dir}/data/test/data.txt"
  echo "output blob" > "${repo_dir}/output/test/out.txt"
}

main() {
  require_cmd git
  require_cmd "$EVC"

  header "ENV CHECK"
  echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID-<unset>}"
  echo "AWS_SECRET_ACCESS_KEY=$( [ -n "${AWS_SECRET_ACCESS_KEY-}" ] && echo '<set>' || echo '<unset>' )"
  echo "AWS_SESSION_TOKEN=$( [ -n "${AWS_SESSION_TOKEN-}" ] && echo '<set>' || echo '<unset>' )"
  echo "AWS_REGION=${AWS_REGION-<unset>}"
  echo "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION-<unset>}"
  echo "EVC_REPO_NAME=${EVC_REPO_NAME-<unset>} (if unset, defaults to folder name)"

  header "1) MODEL REPO: eosdev"
  git_clone_repo "eosdev" "eosdev"

  if [ ! -f "eosdev/access.json" ]; then
    echo "access.json missing after clone. Creating a public model access.json for testing."
    write_access_json_model "eosdev"
  fi

  header "MODEL: view"
  ( cd eosdev && run "$EVC" view )
  ( cd eosdev && run "$EVC" view --path model/checkpoints )
  ( cd eosdev && run "$EVC" view --path model/fit )

  header "MODEL: upload (specific paths)"
  make_dummy_files_model "eosdev"
  ( cd eosdev && run "$EVC" upload --path model/checkpoints/test-run )
  ( cd eosdev && run "$EVC" upload --path model/fit/fit/test-fit )
  ( cd eosdev && run "$EVC" upload --path checkpoints/test-run )
  ( cd eosdev && run "$EVC" upload --path fit/test-fit )

  header "MODEL: upload (all managed roots via --path .)"
  ( cd eosdev && run "$EVC" upload --path . )

  header "MODEL: download (specific paths)"
  ( cd eosdev && run_may_fail "$EVC" download --path model/checkpoints )
  ( cd eosdev && run_may_fail "$EVC" download --path checkpoints )
  ( cd eosdev && run_may_fail "$EVC" download --path fit )

  header "MODEL: download (all managed roots via --path .)"
  ( cd eosdev && run_may_fail "$EVC" download --path . )

  header "2) STANDARD REPO: evc-dev-analysis"
  git_clone_repo "evc-dev-analysis" "evc-dev-analysis"

  if [ ! -f "evc-dev-analysis/access.json" ]; then
    echo "access.json missing after clone. Creating a public standard access.json for testing."
    write_access_json_standard "evc-dev-analysis"
  fi

  header "STANDARD: view"
  ( cd evc-dev-analysis && run "$EVC" view )
  ( cd evc-dev-analysis && run "$EVC" view --path data )
  ( cd evc-dev-analysis && run "$EVC" view --path output )

  header "STANDARD: upload (specific paths)"
  make_dummy_files_standard "evc-dev-analysis"
  ( cd evc-dev-analysis && run "$EVC" upload --path data/test )
  ( cd evc-dev-analysis && run "$EVC" upload --path output/test )

  header "STANDARD: upload (all managed roots via --path .)"
  ( cd evc-dev-analysis && run "$EVC" upload --path . )

  header "STANDARD: download (specific paths)"
  ( cd evc-dev-analysis && run_may_fail "$EVC" download --path data )
  ( cd evc-dev-analysis && run_may_fail "$EVC" download --path output )

  header "STANDARD: download (all managed roots via --path .)"
  ( cd evc-dev-analysis && run_may_fail "$EVC" download --path . )

  header "DONE"
  echo "All commands executed."
}

main "$@"
