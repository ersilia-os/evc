#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from loguru import logger as _loguru
from rich.console import Console
from rich.logging import RichHandler

DEFAULT_ORG = "ersilia-os"
DEFAULT_BRANCH = "main"

BUCKET_PUBLIC = "evc-public"
BUCKET_PRIVATE = "evc-private"

DATA_ROOT = "data"
OUTPUT_ROOTS = {"output"}

MODEL_ROOT = "model"
MODEL_SUBROOTS = {"checkpoints", "framework"}

EVC_META_DIR = ".evc"
ACCESS_LOCK_FILE = "access.lock.json"


class EVCError(RuntimeError):
  pass


class Logger:
  def __init__(self):
    _loguru.remove()
    self.console = Console()
    self._sink_id = None
    self.set_verbosity(True)

  def set_verbosity(self, verbose):
    if self._sink_id is not None:
      try:
        _loguru.remove(self._sink_id)
      except Exception:
        pass
      self._sink_id = None
    if verbose:
      handler = RichHandler(rich_tracebacks=True, markup=True, show_path=False, log_time_format="%H:%M:%S")
      self._sink_id = _loguru.add(handler, format="{message}", colorize=True)

  def debug(self, msg): _loguru.debug(msg)
  def info(self, msg): _loguru.info(msg)
  def warning(self, msg): _loguru.warning(msg)
  def error(self, msg): _loguru.error(msg)
  def success(self, msg): _loguru.success(msg)


logger = Logger()


def bootstrap_env_creds():
  mapping = [
    ("EVC_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
    ("EVC_AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"),
    ("EVC_AWS_SESSION_TOKEN", "AWS_SESSION_TOKEN"),
    ("EVC_AWS_REGION", "AWS_REGION"),
    ("EVC_AWS_DEFAULT_REGION", "AWS_DEFAULT_REGION"),
  ]
  for src, dst in mapping:
    if os.environ.get(dst):
      continue
    v = os.environ.get(src)
    if v:
      os.environ[dst] = v

  os.environ.pop("AWS_PROFILE", None)
  os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
  os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
  os.environ["AWS_CONFIG_FILE"] = "/dev/null"


def env_region():
  return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


def env_creds():
  ak = os.environ.get("AWS_ACCESS_KEY_ID")
  sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
  st = os.environ.get("AWS_SESSION_TOKEN")
  if not ak or not sk:
    return None
  return {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": st}


def have_creds():
  return env_creds() is not None


def require_creds(msg):
  if not have_creds():
    raise EVCError(msg)


def s3_signed():
  creds = env_creds()
  if not creds:
    raise EVCError("AWS credentials required (env vars only).")
  kwargs = {k: v for k, v in creds.items() if v}
  return boto3.client("s3", region_name=env_region(), **kwargs)


def s3_unsigned():
  return boto3.client("s3", region_name=env_region(), config=Config(signature_version=UNSIGNED))


def s3_for_read(bucket):
  if bucket == BUCKET_PUBLIC and not have_creds():
    return s3_unsigned()
  return s3_signed()


def s3_for_write(_bucket):
  require_creds("AWS credentials required for upload/push (env vars only).")
  return s3_signed()


def _normalize_access_value(v):
  v = (v or "").strip().lower()
  if v not in {"public", "private"}:
    raise EVCError(f"Invalid access value '{v}'. Use 'public' or 'private'.")
  return v


class AccessPolicy:
  def __init__(self, data="public", output="public", model="public"):
    self.data = _normalize_access_value(data)
    self.output = _normalize_access_value(output)
    self.model = _normalize_access_value(model)

  def bucket_for(self, category):
    if category == "data":
      return BUCKET_PUBLIC if self.data == "public" else BUCKET_PRIVATE
    if category == "output":
      return BUCKET_PUBLIC if self.output == "public" else BUCKET_PRIVATE
    if category == "model":
      return BUCKET_PUBLIC if self.model == "public" else BUCKET_PRIVATE
    raise EVCError(f"Unknown access category: {category}")

  def to_json(self, mode):
    return {"mode": mode, "data": self.data, "output": self.output, "model": self.model}

  def __eq__(self, other):
    return (
      isinstance(other, AccessPolicy)
      and self.data == other.data
      and self.output == other.output
      and self.model == other.model
    )


def run(cmd, cwd=None):
  try:
    p = subprocess.run(
      cmd,
      cwd=str(cwd) if cwd else None,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
    )
  except FileNotFoundError as e:
    raise EVCError(f"Command not found: {cmd[0]}") from e
  if p.returncode:
    msg = f"Command failed ({p.returncode}): {' '.join(cmd)}\n"
    if p.stdout.strip():
      msg += f"\nSTDOUT:\n{p.stdout}"
    if p.stderr.strip():
      msg += f"\nSTDERR:\n{p.stderr}"
    raise EVCError(msg)
  return p.stdout


def _read_json(p):
  try:
    return json.loads(p.read_text(encoding="utf-8"))
  except Exception as e:
    raise EVCError(f"Failed to parse {p}: {e}") from e


def require_access_json(repo_dir):
  p = repo_dir / "access.json"
  if not p.exists():
    raise EVCError(
      "access.json is required for evc operations in this repo.\n"
      "Create one at repo root, e.g.\n"
      '  {"data":"public","output":"public"}\n'
      "or for model repos:\n"
      '  {"model":"public"}\n'
    )
  return p


def detect_mode(access_dict):
  keys = set((access_dict or {}).keys())
  if "model" in keys and not (("data" in keys) or ("output" in keys) or ("access" in keys)):
    return "model"
  return "standard"


def load_access(repo_dir):
  d = _read_json(require_access_json(repo_dir))
  mode = detect_mode(d)
  policy = AccessPolicy(
    d.get("data", "public"),
    d.get("output", "public"),
    d.get("model", "public"),
  )
  return policy, mode


def ensure_access_lock(repo_dir, policy, mode):
  meta_dir = repo_dir / EVC_META_DIR
  meta_dir.mkdir(exist_ok=True)
  lock_path = meta_dir / ACCESS_LOCK_FILE

  if not lock_path.exists():
    lock_path.write_text(json.dumps(policy.to_json(mode), indent=2) + "\n", encoding="utf-8")
    return

  existing = _read_json(lock_path)
  locked_mode = str(existing.get("mode", "standard")).strip().lower() or "standard"
  locked_policy = AccessPolicy(
    existing.get("data", "public"),
    existing.get("output", "public"),
    existing.get("model", "public"),
  )

  if locked_mode != mode or locked_policy != policy:
    raise EVCError(
      "Access policy change detected (public/private migration is not allowed).\n"
      f"Lock:   {locked_policy.to_json(locked_mode)}\n"
      f"Config: {policy.to_json(mode)}\n"
      f"If this is intentional, delete {lock_path} manually (NOT recommended)."
    )


def ensure_clean_repo(repo_dir):
  status = run(["git", "status", "--porcelain"], cwd=repo_dir)
  if status.strip():
    raise EVCError("Working tree is dirty. Commit your changes before evc push.")


def confirm(prompt, assume_yes=False):
  if assume_yes:
    return True
  try:
    ans = input(f"{prompt} [y/N]: ").strip().lower()
  except EOFError:
    return False
  return ans in {"y", "yes"}


def git_repo_root(start):
  return Path(run(["git", "rev-parse", "--show-toplevel"], cwd=start).strip())


def git_origin_url(repo_dir):
  return run(["git", "config", "--get", "remote.origin.url"], cwd=repo_dir).strip()


def repo_name_from_origin(origin_url):
  s = origin_url.strip()
  if s.endswith(".git"):
    s = s[:-4]
  if "/" in s:
    name = s.rsplit("/", 1)[-1]
  elif ":" in s:
    name = s.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
  else:
    name = s
  if not name:
    raise EVCError(f"Could not infer repo name from origin URL: {origin_url}")
  return name


def iter_local_files(path):
  if path.is_file():
    yield path
    return
  for p in path.rglob("*"):
    if p.is_file():
      yield p


def s3_list_keys(client, bucket, prefix):
  keys = []
  token = None
  try:
    while True:
      kwargs = {"Bucket": bucket, "Prefix": prefix}
      if token:
        kwargs["ContinuationToken"] = token
      resp = client.list_objects_v2(**kwargs)
      for obj in resp.get("Contents") or []:
        keys.append(obj["Key"])
      if not resp.get("IsTruncated"):
        break
      token = resp.get("NextContinuationToken")
  except (BotoCoreError, ClientError) as e:
    raise EVCError(f"S3 error listing s3://{bucket}/{prefix}: {e}") from e
  return keys


def s3_download_prefix(client, bucket, prefix, dest_dir):
  keys = [k for k in s3_list_keys(client, bucket, prefix) if not k.endswith("/")]
  if not keys:
    logger.info(f"No objects found in s3://{bucket}/{prefix} (skipping).")
    return
  for key in keys:
    rel = key[len(prefix):].lstrip("/")
    local_path = dest_dir / rel
    local_path.parent.mkdir(parents=True, exist_ok=True)
    try:
      client.download_file(bucket, key, str(local_path))
    except (BotoCoreError, ClientError) as e:
      raise EVCError(f"S3 download failed s3://{bucket}/{key}: {e}") from e


def s3_download_path(client, bucket, repo_prefix, rel_path, repo_dir):
  rel_path = rel_path.strip().lstrip("/")
  base = repo_prefix.rstrip("/") + "/"
  file_key = base + rel_path
  dir_prefix = base + rel_path.rstrip("/") + "/"

  exact = [k for k in s3_list_keys(client, bucket, file_key) if k == file_key]
  if exact:
    dest = repo_dir / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
      client.download_file(bucket, file_key, str(dest))
    except (BotoCoreError, ClientError) as e:
      raise EVCError(f"S3 download failed s3://{bucket}/{file_key}: {e}") from e
    return

  keys = [k for k in s3_list_keys(client, bucket, dir_prefix) if not k.endswith("/")]
  if not keys:
    raise EVCError(f"Nothing found at s3://{bucket}/{file_key} or s3://{bucket}/{dir_prefix}")

  for key in keys:
    rel = key[len(base):].lstrip("/")
    dest = repo_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
      client.download_file(bucket, key, str(dest))
    except (BotoCoreError, ClientError) as e:
      raise EVCError(f"S3 download failed s3://{bucket}/{key}: {e}") from e


def s3_upload_path(client, bucket, repo_prefix, src_path, repo_dir):
  src_path = (repo_dir / src_path).resolve() if not src_path.is_absolute() else src_path.resolve()
  if not src_path.exists():
    raise EVCError(f"Path does not exist: {src_path}")

  repo_dir_abs = repo_dir.resolve()
  for file_path in iter_local_files(src_path):
    rel = file_path.relative_to(repo_dir_abs).as_posix()
    key = f"{repo_prefix.rstrip('/')}/{rel}"
    try:
      client.upload_file(str(file_path), bucket, key)
    except (BotoCoreError, ClientError) as e:
      raise EVCError(f"S3 upload failed {file_path} -> s3://{bucket}/{key}: {e}") from e


def s3_print_tree(keys, base_prefix):
  base_prefix = base_prefix.rstrip("/") + "/"
  rels = []
  for k in keys:
    if k.startswith(base_prefix):
      rel = k[len(base_prefix):].lstrip("/")
      if rel:
        rels.append(rel)

  if not rels:
    logger.info("(empty)")
    return

  tree = {}
  for rel in rels:
    parts = [p for p in rel.split("/") if p]
    node = tree
    for p in parts[:-1]:
      node = node.setdefault(p, {})
    node.setdefault(parts[-1], {})

  def walk(node, prefix=""):
    items = sorted(node.items(), key=lambda x: x[0])
    for i, (name, child) in enumerate(items):
      last = i == len(items) - 1
      logger.info(prefix + ("└── " if last else "├── ") + name)
      if child:
        walk(child, prefix + ("    " if last else "│   "))

  walk(tree)


def artifacts_plan(mode):
  if mode == "model":
    return [(f"{MODEL_ROOT}/{s}", "model") for s in sorted(MODEL_SUBROOTS)]
  plan = [(DATA_ROOT, "data")]
  plan += [(r, "output") for r in sorted(OUTPUT_ROOTS)]
  return plan


def resolve_category_for_path(rel_path, mode):
  rel_path = rel_path.strip().lstrip("/")
  if not rel_path:
    raise EVCError("--path is required")
  root = rel_path.split("/", 1)[0]
  if mode == "model":
    if root != MODEL_ROOT:
      raise EVCError("Model repo: only 'model/...' paths are supported.")
    return "model"
  if root == DATA_ROOT:
    return "data"
  if root in OUTPUT_ROOTS:
    return "output"
  raise EVCError(f"Unsupported path root '{root}'.")


def ensure_on_main(repo_dir):
  branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir).strip()
  if branch != DEFAULT_BRANCH:
    logger.warning(f"Current branch is '{branch}'. Switching to '{DEFAULT_BRANCH}'.")
    run(["git", "checkout", DEFAULT_BRANCH], cwd=repo_dir)


def cmd_clone(args):
  repo = (args.repo or "").strip()
  if not repo:
    raise EVCError("Repo name is required, e.g. evc clone <repo>")

  org = args.org or DEFAULT_ORG
  url = f"https://github.com/{org}/{repo}.git"
  dest = Path(args.dest or repo).resolve()
  if dest.exists():
    raise EVCError(f"Destination already exists: {dest}")

  logger.info(f"Cloning {url} (branch: {DEFAULT_BRANCH}) -> {dest}")
  run(["git", "clone", "--branch", DEFAULT_BRANCH, "--single-branch", url, str(dest)])
  ensure_on_main(dest)

  access_path = dest / "access.json"
  if not access_path.exists():
    logger.warning("Clone complete (git only). access.json not found; all other evc operations are disabled until you add access.json.")
    logger.success("Clone complete.")
    return

  policy, mode = load_access(dest)
  ensure_access_lock(dest, policy, mode)
  logger.info(f"Access: {policy.to_json(mode)}")

  if mode == "standard":
    data_private = policy.data == "private"
    output_private = policy.output == "private"
    if data_private and output_private:
      require_creds("AWS credentials required to clone this repo: both data and output are private.")
    if (data_private or output_private) and not have_creds():
      if not data_private:
        logger.warning("No AWS credentials found: skipping private output; downloading public data only.")
      elif not output_private:
        logger.warning("No AWS credentials found: skipping private data; downloading public output only.")
  else:
    if policy.model == "private":
      require_creds("AWS credentials required to clone this repo: model is private.")

  for rel_dir, category in artifacts_plan(mode):
    if mode == "standard" and category == "data" and policy.data == "private" and not have_creds():
      logger.warning("Skipping download of private data (no credentials).")
      continue
    if mode == "standard" and category == "output" and policy.output == "private" and not have_creds():
      logger.warning("Skipping download of private output (no credentials).")
      continue
    if mode == "model" and policy.model == "private" and not have_creds():
      raise EVCError("AWS credentials required to download private model artifacts.")

    bucket = policy.bucket_for(category)
    client = s3_for_read(bucket)
    prefix = f"{repo}/{rel_dir}/"
    dest_dir = dest / rel_dir
    logger.info(f"Downloading {rel_dir}/ from s3://{bucket}/{prefix} -> {dest_dir}")
    s3_download_prefix(client, bucket, prefix, dest_dir)

  logger.success("Clone complete.")


def cmd_pull(args):
  repo_dir = git_repo_root(Path.cwd())
  ensure_on_main(repo_dir)

  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)

  repo = repo_name_from_origin(git_origin_url(repo_dir))

  logger.info(f"Git pull --rebase (origin/{DEFAULT_BRANCH})")
  run(["git", "pull", "--rebase", "origin", DEFAULT_BRANCH], cwd=repo_dir)

  to_delete = []
  for rel_dir, _ in artifacts_plan(mode):
    p = repo_dir / rel_dir
    if p.exists():
      to_delete.append(p)

  if to_delete:
    listing = "\n".join(f"  - {p.relative_to(repo_dir)}" for p in to_delete)
    if not confirm(
      f"This will delete existing artifact folders before re-downloading:\n{listing}\nProceed?",
      assume_yes=args.yes,
    ):
      raise EVCError("Aborted by user.")
    for p in to_delete:
      logger.info(f"Deleting {p.relative_to(repo_dir)}")
      if p.is_dir():
        shutil.rmtree(p)
      else:
        p.unlink()

  for rel_dir, category in artifacts_plan(mode):
    bucket = policy.bucket_for(category)
    if bucket == BUCKET_PRIVATE:
      require_creds("AWS credentials required to read from evc-private (env vars only).")
    client = s3_for_read(bucket)
    prefix = f"{repo}/{rel_dir}/"
    dest_dir = repo_dir / rel_dir
    logger.info(f"Downloading {rel_dir}/ from s3://{bucket}/{prefix} -> {dest_dir}")
    s3_download_prefix(client, bucket, prefix, dest_dir)

  logger.success("Pull complete.")


def cmd_push(_args):
  repo_dir = git_repo_root(Path.cwd())
  ensure_on_main(repo_dir)

  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)

  repo = repo_name_from_origin(git_origin_url(repo_dir))

  require_creds("AWS credentials required for upload/push (env vars only).")
  ensure_clean_repo(repo_dir)

  logger.info(f"Git push (origin/{DEFAULT_BRANCH})")
  run(["git", "push", "origin", DEFAULT_BRANCH], cwd=repo_dir)

  for rel_dir, category in artifacts_plan(mode):
    local_dir = repo_dir / rel_dir
    if not local_dir.exists():
      continue
    bucket = policy.bucket_for(category)
    client = s3_for_write(bucket)
    logger.info(f"Uploading {rel_dir}/ -> s3://{bucket}/{repo}/{rel_dir}/")
    s3_upload_path(client, bucket, repo, local_dir.relative_to(repo_dir), repo_dir)

  logger.success("Push complete.")


def cmd_download(args):
  repo_dir = git_repo_root(Path.cwd())

  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)

  repo = repo_name_from_origin(git_origin_url(repo_dir))

  rel_path = (args.path or "").strip()
  category = resolve_category_for_path(rel_path, mode)
  bucket = policy.bucket_for(category)
  if bucket == BUCKET_PRIVATE:
    require_creds("AWS credentials required to read from evc-private (env vars only).")
  client = s3_for_read(bucket)
  logger.info(f"Downloading --path {rel_path} from s3://{bucket}/{repo}/")
  s3_download_path(client, bucket, repo, rel_path, repo_dir)
  logger.success("Download complete.")


def cmd_upload(args):
  repo_dir = git_repo_root(Path.cwd())

  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)

  repo = repo_name_from_origin(git_origin_url(repo_dir))

  rel_path = (args.path or "").strip()
  category = resolve_category_for_path(rel_path, mode)
  bucket = policy.bucket_for(category)
  client = s3_for_write(bucket)
  logger.info(f"Uploading --path {rel_path} to s3://{bucket}/{repo}/")
  s3_upload_path(client, bucket, repo, Path(rel_path), repo_dir)
  logger.success("Upload complete.")


def cmd_view(args):
  repo_dir = git_repo_root(Path.cwd())

  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)

  repo = repo_name_from_origin(git_origin_url(repo_dir))

  rel_path = (args.path or ".").strip().lstrip("/")

  def show(category, prefix, title):
    bucket = policy.bucket_for(category)
    if bucket == BUCKET_PRIVATE:
      require_creds("AWS credentials required to view evc-private (env vars only).")
    client = s3_for_read(bucket)
    logger.info(title)
    s3_print_tree(s3_list_keys(client, bucket, prefix), prefix)
    logger.info("")

  if rel_path in {"", "."}:
    for rel_dir, category in artifacts_plan(mode):
      b = policy.bucket_for(category)
      show(category, f"{repo}/{rel_dir}/", f"[{rel_dir}] s3://{b}/{repo}/{rel_dir}/")
    return

  category = resolve_category_for_path(rel_path, mode)
  b = policy.bucket_for(category)
  show(category, f"{repo}/{rel_path.rstrip('/')}/", f"s3://{b}/{repo}/{rel_path.rstrip('/')}/")


