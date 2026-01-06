#!/usr/bin/env bash
set -euo pipefail

EVC="${EVC:-eosvc}"   

run() {
  echo
  echo "==> $*"
  "$@"
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

write_access_json_model() {
  local repo_dir="$1"
  cat > "${repo_dir}/access.json" <<'JSON'
{
  "checkpoints": "public",
  "framework": "public"
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
  mkdir -p "${repo_dir}/model/framework/fit/test-fit"
  echo "checkpoint blob" > "${repo_dir}/model/checkpoints/test-run/ckpt.txt"
  echo "framework blob" > "${repo_dir}/model/framework/fit/test-fit/fw.txt"
}

make_dummy_files_standard() {
  local repo_dir="$1"
  mkdir -p "${repo_dir}/data/test"
  mkdir -p "${repo_dir}/output/test"
  echo "data blob" > "${repo_dir}/data/test/data.txt"
  echo "output blob" > "${repo_dir}/output/test/out.txt"
}

git_commit_if_possible() {
  local repo_dir="$1"
  pushd "$repo_dir" >/dev/null
  git status --porcelain >/dev/null 2>&1 || { popd >/dev/null; return; }
  if [ -n "$(git status --porcelain)" ]; then
    git add -A
    git commit -m "test: evc artifacts update" || true
  fi
  popd >/dev/null
}

main() {
  require_cmd git

  header "ENV CHECK (EVC uses env-only AWS creds)"
  echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID-<unset>}"
  echo "AWS_SECRET_ACCESS_KEY=$( [ -n "${AWS_SECRET_ACCESS_KEY-}" ] && echo '<set>' || echo '<unset>' )"
  echo "AWS_SESSION_TOKEN=$( [ -n "${AWS_SESSION_TOKEN-}" ] && echo '<set>' || echo '<unset>' )"
  echo "AWS_REGION=${AWS_REGION-<unset>}"
  echo "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION-<unset>}"

  header "1) MODEL REPO: eosdev"
  ensure_clean_dir eosdev
  run "$EVC" clone eosdev

  if [ ! -f "eosdev/access.json" ]; then
    echo "access.json missing after clone. Creating a public model access.json for testing."
    write_access_json_model "eosdev"
  fi

  header "MODEL: view (root + checkpoints + framework)"
  ( cd eosdev && run "$EVC" view )
  ( cd eosdev && run "$EVC" view --path model/checkpoints )
  ( cd eosdev && run "$EVC" view --path model/framework )



  header "MODEL: upload examples (requires env AWS creds)"
  make_dummy_files_model "eosdev"
  ( cd eosdev && run "$EVC" upload --path model/checkpoints/test-run )
  ( cd eosdev && run "$EVC" upload --path model/framework/fit/test-fit )
  ( cd eosdev && run "$EVC" upload --path checkpoints/test-run )   
  ( cd eosdev && run "$EVC" upload --path framework/test-fit )    

  header "MODEL: download examples"
  ( cd eosdev && run "$EVC" download --path model/checkpoints )
  ( cd eosdev && run "$EVC" download --path checkpoints )         
  ( cd eosdev && run "$EVC" download --path framework )          

  header "MODEL: pull"
  ( cd eosdev && run "$EVC" pull -y )

  header "MODEL: push (requires clean git, do a commit first)"
  git_commit_if_possible "eosdev"
  ( cd eosdev && run "$EVC" push )

  header "2) STANDARD REPO (data/output): evc-dev-analysis"
  ensure_clean_dir evc-dev-analysis
  run "$EVC" clone evc-dev-analysis

  if [ ! -f "evc-dev-analysis/access.json" ]; then
    echo "access.json missing after clone. Creating a public standard access.json for testing."
    write_access_json_standard "evc-dev-analysis"
  fi

  header "STANDARD: view (root + data + output)"
  ( cd evc-dev-analysis && run "$EVC" view )
  ( cd evc-dev-analysis && run "$EVC" view --path data )
  ( cd evc-dev-analysis && run "$EVC" view --path output )

  header "STANDARD: download examples"
  ( cd evc-dev-analysis && run "$EVC" download --path data )
  ( cd evc-dev-analysis && run "$EVC" download --path output )

  header "STANDARD: upload examples (requires env AWS creds)"
  make_dummy_files_standard "evc-dev-analysis"
  ( cd evc-dev-analysis && run "$EVC" upload --path data/test )
  ( cd evc-dev-analysis && run "$EVC" upload --path output/test )

  header "STANDARD: pull"
  ( cd evc-dev-analysis && run "$EVC" pull -y )

  header "STANDARD: push (requires clean git, do a commit first)"
  git_commit_if_possible "evc-dev-analysis"
  ( cd evc-dev-analysis && run "$EVC" push )

  header "DONE"
  echo "All commands executed."
}

main "$@"
