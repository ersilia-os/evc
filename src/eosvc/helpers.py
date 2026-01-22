import boto3, json, os, subprocess
from pathlib import Path

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from loguru import logger as _loguru
from rich.console import Console
from rich.logging import RichHandler


BUCKET_PUBLIC = "eosvc-public"
BUCKET_PRIVATE = "eosvc-private"

DATA_ROOT = "data"
OUTPUT_ROOT = "output"

MODEL_ROOT = "model"
MODEL_CHECKPOINTS = "model/checkpoints"
MODEL_FRAMEWORK_FIT = "model/fit"

EOSVC_META_DIR = ".eosvc"
ACCESS_LOCK_FILE = "access.lock.json"

EOSVC_HOME_DIR = Path.home() / ".eosvc"
EOSVC_HOME_ENV = EOSVC_HOME_DIR / ".config"


class EOSVCError(RuntimeError):
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
      handler = RichHandler(
        rich_tracebacks=True, markup=True, show_path=False, log_time_format="%H:%M:%S"
      )
      self._sink_id = _loguru.add(handler, format="{message}", colorize=True)

  def debug(self, msg):
    _loguru.debug(msg)

  def info(self, msg):
    _loguru.info(msg)

  def warning(self, msg):
    _loguru.warning(msg)

  def error(self, msg):
    _loguru.error(msg)

  def success(self, msg):
    _loguru.success(msg)


logger = Logger()


def env_region():
  return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


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
    raise EOSVCError(f"Command not found: {cmd[0]}") from e
  if p.returncode:
    msg = f"Command failed ({p.returncode}): {' '.join(cmd)}\n"
    if p.stdout.strip():
      msg += f"\nSTDOUT:\n{p.stdout}"
    if p.stderr.strip():
      msg += f"\nSTDERR:\n{p.stderr}"
    raise EOSVCError(msg)
  return p.stdout


def _read_json(p):
  try:
    return json.loads(p.read_text(encoding="utf-8"))
  except Exception as e:
    raise EOSVCError(f"Failed to parse {p}: {e}") from e


def _normalize_access_value(v):
  v = (v or "").strip().lower()
  if v not in {"public", "private"}:
    raise EOSVCError(f"Invalid access value '{v}'. Use 'public' or 'private'.")
  return v


class AccessPolicy:
  def __init__(self, data=None, output=None, checkpoints=None, fit=None):
    self.data = _normalize_access_value(data) if data is not None else None
    self.output = _normalize_access_value(output) if output is not None else None
    self.checkpoints = _normalize_access_value(checkpoints) if checkpoints is not None else None
    self.fit = _normalize_access_value(fit) if fit is not None else None

  def bucket_for(self, category):
    if category == "data":
      return BUCKET_PUBLIC if self.data == "public" else BUCKET_PRIVATE
    if category == "output":
      return BUCKET_PUBLIC if self.output == "public" else BUCKET_PRIVATE
    if category == "checkpoints":
      return BUCKET_PUBLIC if self.checkpoints == "public" else BUCKET_PRIVATE
    if category == "fit":
      return BUCKET_PUBLIC if self.fit == "public" else BUCKET_PRIVATE
    raise EOSVCError(f"Unknown access category: {category}")

  def to_json(self, mode):
    if mode == "standard":
      return {"mode": mode, "data": self.data, "output": self.output}
    return {"mode": mode, "checkpoints": self.checkpoints, "fit": self.fit}

  def __eq__(self, other):
    return (
      isinstance(other, AccessPolicy)
      and self.data == other.data
      and self.output == other.output
      and self.checkpoints == other.checkpoints
      and self.fit == other.fit
    )


class CredManager:
  def __init__(self):
    self._session = None
    self._source = None
    self._caller_arn = None
    self._checked = False

  def reset(self):
    self._session = None
    self._source = None
    self._caller_arn = None
    self._checked = False

  def _try_sts(self, session):
    try:
      sts = session.client("sts", region_name=env_region())
      ident = sts.get_caller_identity()
      arn = ident.get("Arn")
      return arn or "<unknown-arn>"
    except Exception:
      return None

  def _dotenv_paths(self, repo_dir):
    paths = []
    paths.append(EOSVC_HOME_ENV)
    if repo_dir:
      paths.append(Path(repo_dir) / ".env")
    paths.append(Path.cwd() / ".env")
    seen = set()
    out = []
    for p in paths:
      rp = str(p.resolve()) if p.exists() else str(p)
      if rp not in seen:
        seen.add(rp)
        out.append(p)
    return out

  def _load_dotenv(self, repo_dir):
    try:
      from dotenv import load_dotenv
    except Exception:
      raise EOSVCError(
        "python-dotenv is required for .env fallback. Install: pip install python-dotenv"
      )

    loaded_any = False
    for p in self._dotenv_paths(repo_dir):
      if p.exists():
        load_dotenv(dotenv_path=str(p), override=True)
        loaded_any = True
    return loaded_any

  def _has_aws_files(self):
    home = Path.home()
    cred = home / ".aws" / "credentials"
    conf = home / ".aws" / "config"
    return cred.exists() or conf.exists()

  def resolve(self, repo_dir=None, require=False):
    if self._checked:
      if require and self._session is None:
        raise EOSVCError(self._missing_message(repo_dir))
      return self._session, self._source, self._caller_arn

    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

    session = boto3.Session(region_name=env_region())
    creds = session.get_credentials()
    if creds:
      arn = self._try_sts(session)
      if arn:
        self._session = session
        self._source = "aws-default-chain (env and/or ~/.aws)"
        self._caller_arn = arn
        self._checked = True
        return self._session, self._source, self._caller_arn
      logger.warning(
        "AWS credentials found (env and/or ~/.aws) but validation failed (sts:GetCallerIdentity). Trying .env fallback."
      )
    else:
      if self._has_aws_files():
        logger.warning(
          "Found ~/.aws credentials/config files but boto3 did not resolve credentials. Trying .env fallback."
        )
      else:
        logger.warning("No AWS credentials found in env or ~/.aws. Trying .env fallback.")

    loaded = self._load_dotenv(repo_dir)
    if loaded:
      session2 = boto3.Session(region_name=env_region())
      creds2 = session2.get_credentials()
      if creds2:
        arn2 = self._try_sts(session2)
        if arn2:
          self._session = session2
          self._source = ".env (python-dotenv)"
          self._caller_arn = arn2
          self._checked = True
          return self._session, self._source, self._caller_arn
        logger.warning(
          "Loaded .env but credentials still failed validation (sts:GetCallerIdentity)."
        )
      else:
        logger.warning("Loaded .env but boto3 still did not resolve credentials.")
    else:
      logger.warning("No .env file found for fallback.")

    self._session = None
    self._source = None
    self._caller_arn = None
    self._checked = True

    if require:
      raise EOSVCError(self._missing_message(repo_dir))
    return None, None, None

  def _missing_message(self, repo_dir):
    env_hint = (
      "Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (and optional AWS_SESSION_TOKEN), "
      "or configure AWS CLI (aws configure), or run 'eosvc config' to write ~/.eosvc/.env."
    )
    searched = [str(p) for p in self._dotenv_paths(repo_dir)]
    return (
      "AWS credentials are missing or invalid.\n"
      f"- Checked: env and ~/.aws\n"
      f"- Checked .env paths: {', '.join(searched)}\n"
      f"- Fix: {env_hint}"
    )


CREDS = CredManager()


def s3_unsigned():
  return boto3.client("s3", region_name=env_region(), config=Config(signature_version=UNSIGNED))


def s3_for_read(bucket, repo_dir):
  if bucket == BUCKET_PUBLIC:
    session, _, _ = CREDS.resolve(repo_dir=repo_dir, require=False)
    if session is None:
      return s3_unsigned()
    return session.client("s3", region_name=env_region())
  session, _, _ = CREDS.resolve(repo_dir=repo_dir, require=True)
  return session.client("s3", region_name=env_region())


def s3_for_write(bucket, repo_dir):
  session, source, arn = CREDS.resolve(repo_dir=repo_dir, require=True)
  if session is None:
    raise EOSVCError("AWS credentials required for upload.")
  logger.info(f"Using AWS credentials from: {source} ({arn})")
  return session.client("s3", region_name=env_region())


def require_access_json(repo_dir):
  p = repo_dir / "access.json"
  if not p.exists():
    raise EOSVCError("access.json is required for eosvc operations in this folder.")
  return p


def find_repo_root(start_dir):
  p = Path(start_dir).resolve()
  for cur in [p] + list(p.parents):
    if (cur / "access.json").exists():
      return cur
  raise EOSVCError("Could not find access.json in this folder or any parent folder.")


def repo_name(repo_dir):
  v = (os.environ.get("EVC_REPO_NAME") or "").strip()
  return v if v else repo_dir.name


def detect_mode(d):
  keys = set((d or {}).keys())
  has_std = ("data" in keys) or ("output" in keys)
  has_model = ("checkpoints" in keys) or ("fit" in keys)
  if has_std and has_model:
    raise EOSVCError(
      "access.json cannot mix standard keys (data/output) with model keys (checkpoints/fit)."
    )
  if has_model:
    return "model"
  return "standard"


def load_access(repo_dir):
  d = _read_json(require_access_json(repo_dir))
  mode = detect_mode(d)
  if mode == "model":
    policy = AccessPolicy(
      checkpoints=d.get("checkpoints", "public"),
      fit=d.get("fit", "public"),
    )
  else:
    policy = AccessPolicy(
      data=d.get("data", "public"),
      output=d.get("output", "public"),
    )
  return policy, mode


def ensure_access_lock(repo_dir, policy, mode):
  meta_dir = repo_dir / EOSVC_META_DIR
  meta_dir.mkdir(exist_ok=True)
  lock_path = meta_dir / ACCESS_LOCK_FILE

  if not lock_path.exists():
    lock_path.write_text(json.dumps(policy.to_json(mode), indent=2) + "\n", encoding="utf-8")
    return

  existing = _read_json(lock_path)
  locked_mode = str(existing.get("mode", "standard")).strip().lower() or "standard"
  if locked_mode == "model":
    locked_policy = AccessPolicy(
      checkpoints=existing.get("checkpoints", "public"),
      fit=existing.get("fit", "public"),
    )
  else:
    locked_policy = AccessPolicy(
      data=existing.get("data", "public"),
      output=existing.get("output", "public"),
    )

  if locked_mode != mode or locked_policy != policy:
    raise EOSVCError(
      "Access policy change detected (public/private migration is not allowed).\n"
      f"Lock:   {locked_policy.to_json(locked_mode)}\n"
      f"Config: {policy.to_json(mode)}\n"
      f"If this is intentional, delete {lock_path} manually (NOT recommended)."
    )


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
    raise EOSVCError(f"S3 error listing s3://{bucket}/{prefix}: {e}") from e
  return keys


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
      raise EOSVCError(f"S3 download failed s3://{bucket}/{file_key}: {e}") from e
    return

  keys = [k for k in s3_list_keys(client, bucket, dir_prefix) if not k.endswith("/")]
  if not keys:
    raise EOSVCError(f"Nothing found at s3://{bucket}/{file_key} or s3://{bucket}/{dir_prefix}")

  for key in keys:
    rel = key[len(base) :].lstrip("/")
    dest = repo_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
      client.download_file(bucket, key, str(dest))
    except (BotoCoreError, ClientError) as e:
      raise EOSVCError(f"S3 download failed s3://{bucket}/{key}: {e}") from e


def s3_upload_path(client, bucket, repo_prefix, src_path, repo_dir):
  src_path = (repo_dir / src_path).resolve() if not src_path.is_absolute() else src_path.resolve()
  if not src_path.exists():
    raise EOSVCError(f"Path does not exist: {src_path}")

  repo_dir_abs = repo_dir.resolve()
  for file_path in iter_local_files(src_path):
    rel = file_path.relative_to(repo_dir_abs).as_posix()
    key = f"{repo_prefix.rstrip('/')}/{rel}"
    try:
      client.upload_file(str(file_path), bucket, key)
    except (BotoCoreError, ClientError) as e:
      raise EOSVCError(f"S3 upload failed {file_path} -> s3://{bucket}/{key}: {e}") from e


def s3_print_tree(keys, base_prefix):
  base_prefix = base_prefix.rstrip("/") + "/"
  rels = []
  for k in keys:
    if k.startswith(base_prefix):
      rel = k[len(base_prefix) :].lstrip("/")
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
    return [(MODEL_CHECKPOINTS, "checkpoints"), (MODEL_FRAMEWORK_FIT, "fit")]
  return [(DATA_ROOT, "data"), (OUTPUT_ROOT, "output")]


def normalize_user_path(path, mode):
  p = (path or "").strip().lstrip("/")
  if not p:
    raise EOSVCError("--path is required")

  if mode == "standard":
    root = p.split("/", 1)[0]
    if root not in {DATA_ROOT, OUTPUT_ROOT}:
      raise EOSVCError(f"Unsupported path '{p}'. Allowed roots: {DATA_ROOT}/, {OUTPUT_ROOT}/")
    return p

  if p.startswith(MODEL_ROOT + "/"):
    if p.startswith(MODEL_CHECKPOINTS) or p.startswith(MODEL_FRAMEWORK_FIT):
      return p
    if p.startswith("model/fit"):
      rest = p[len("model/fit") :].lstrip("/")
      return f"{MODEL_FRAMEWORK_FIT}/{rest}".rstrip("/")
    raise EOSVCError(
      f"Model repo: only '{MODEL_CHECKPOINTS}/...' or '{MODEL_FRAMEWORK_FIT}/...' are supported."
    )

  if p.startswith("checkpoints"):
    rest = p[len("checkpoints") :].lstrip("/")
    return f"{MODEL_CHECKPOINTS}/{rest}".rstrip("/")

  if p.startswith("fit"):
    rest = p[len("fit") :].lstrip("/")
    return f"{MODEL_FRAMEWORK_FIT}/{rest}".rstrip("/")

  raise EOSVCError(
    "Model repo: only 'model/...', 'checkpoints/...', or 'fit/...' paths are supported."
  )


def category_for_path(path, mode):
  p = path.strip().lstrip("/")
  if mode == "standard":
    if p.startswith(DATA_ROOT):
      return "data"
    if p.startswith(OUTPUT_ROOT):
      return "output"
    raise EOSVCError(f"Unsupported path '{p}'.")
  if p.startswith(MODEL_CHECKPOINTS):
    return "checkpoints"
  if p.startswith(MODEL_FRAMEWORK_FIT) or p.startswith("model/fit"):
    return "fit"
  raise EOSVCError(f"Unsupported model path '{p}'.")


def write_home_env(
  access_key_id, secret_access_key, session_token=None, region=None, default_region=None
):
  EOSVC_HOME_DIR.mkdir(parents=True, exist_ok=True)
  lines = []
  lines.append(f"AWS_ACCESS_KEY_ID={access_key_id.strip()}")
  lines.append(f"AWS_SECRET_ACCESS_KEY={secret_access_key.strip()}")
  if session_token:
    lines.append(f"AWS_SESSION_TOKEN={session_token.strip()}")
  if region:
    lines.append(f"AWS_REGION={region.strip()}")
  if default_region:
    lines.append(f"AWS_DEFAULT_REGION={default_region.strip()}")
  EOSVC_HOME_ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
  try:
    os.chmod(EOSVC_HOME_ENV, 0o600)
  except Exception:
    pass


def cmd_config(args):
  akid = (args.access_key_id or "").strip()
  sak = (args.secret_access_key or "").strip()
  if not akid or not sak:
    raise EOSVCError("--access-key-id and --secret-access-key are required")
  write_home_env(
    access_key_id=akid,
    secret_access_key=sak,
    session_token=(args.session_token or "").strip() or None,
    region=(args.region or "").strip() or None,
    default_region=(args.default_region or "").strip() or None,
  )
  CREDS.reset()
  logger.success(f"Wrote credentials to {EOSVC_HOME_ENV}")


def cmd_download(args):
  repo_dir = find_repo_root(Path.cwd())
  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)
  repo = repo_name(repo_dir)

  rel_path_raw = (args.path or "").strip().lstrip("/")

  if rel_path_raw in {"", ".", "./"}:
    for rel_dir, cat in artifacts_plan(mode):
      bucket = policy.bucket_for(cat)
      if bucket == BUCKET_PRIVATE:
        CREDS.resolve(repo_dir=repo_dir, require=True)
      client = s3_for_read(bucket, repo_dir)
      logger.info(f"Downloading --path {rel_dir} from s3://{bucket}/{repo}/")
      try:
        s3_download_path(client, bucket, repo, rel_dir, repo_dir)
      except EOSVCError as e:
        if "AccessDenied" in str(e):
          _, source, arn = CREDS.resolve(repo_dir=repo_dir, require=False)
          hint = f" (credentials source: {source}, principal: {arn})" if source else " (no credentials)"
          raise EOSVCError(str(e) + hint)
        raise
    logger.success("Download complete.")
    return

  rel_path = normalize_user_path(rel_path_raw, mode)
  cat = category_for_path(rel_path, mode)
  bucket = policy.bucket_for(cat)
  if bucket == BUCKET_PRIVATE:
    CREDS.resolve(repo_dir=repo_dir, require=True)

  client = s3_for_read(bucket, repo_dir)
  logger.info(f"Downloading --path {rel_path} from s3://{bucket}/{repo}/")
  try:
    s3_download_path(client, bucket, repo, rel_path, repo_dir)
  except EOSVCError as e:
    if "AccessDenied" in str(e):
      _, source, arn = CREDS.resolve(repo_dir=repo_dir, require=False)
      hint = f" (credentials source: {source}, principal: {arn})" if source else " (no credentials)"
      raise EOSVCError(str(e) + hint)
    raise
  logger.success("Download complete.")


def cmd_upload(args):
  repo_dir = find_repo_root(Path.cwd())
  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)
  repo = repo_name(repo_dir)

  rel_path_raw = (args.path or "").strip().lstrip("/")

  if rel_path_raw in {"", ".", "./"}:
    for rel_dir, cat in artifacts_plan(mode):
      local_dir = repo_dir / rel_dir
      if not local_dir.exists():
        continue
      bucket = policy.bucket_for(cat)
      client = s3_for_write(bucket, repo_dir)
      logger.info(f"Uploading --path {rel_dir} to s3://{bucket}/{repo}/")
      try:
        s3_upload_path(client, bucket, repo, Path(rel_dir), repo_dir)
      except EOSVCError as e:
        if "AccessDenied" in str(e):
          _, source, arn = CREDS.resolve(repo_dir=repo_dir, require=False)
          raise EOSVCError(str(e) + f" (credentials source: {source}, principal: {arn})")
        raise
    logger.success("Upload complete.")
    return

  rel_path = normalize_user_path(rel_path_raw, mode)
  cat = category_for_path(rel_path, mode)
  bucket = policy.bucket_for(cat)

  client = s3_for_write(bucket, repo_dir)
  logger.info(f"Uploading --path {rel_path} to s3://{bucket}/{repo}/")
  try:
    s3_upload_path(client, bucket, repo, Path(rel_path), repo_dir)
  except EOSVCError as e:
    if "AccessDenied" in str(e):
      _, source, arn = CREDS.resolve(repo_dir=repo_dir, require=False)
      raise EOSVCError(str(e) + f" (credentials source: {source}, principal: {arn})")
    raise
  logger.success("Upload complete.")


def cmd_view(args):
  repo_dir = find_repo_root(Path.cwd())
  policy, mode = load_access(repo_dir)
  ensure_access_lock(repo_dir, policy, mode)
  repo = repo_name(repo_dir)

  rel_path = (args.path or ".").strip().lstrip("/")
  if rel_path in {"", "."}:
    for rel_dir, cat in artifacts_plan(mode):
      bucket = policy.bucket_for(cat)
      if bucket == BUCKET_PRIVATE:
        CREDS.resolve(repo_dir=repo_dir, require=True)
      client = s3_for_read(bucket, repo_dir)
      prefix = f"{repo}/{rel_dir}/"
      logger.info(f"[{rel_dir}] s3://{bucket}/{prefix}")
      s3_print_tree(s3_list_keys(client, bucket, prefix), prefix)
      logger.info("")
    return

  rel_path = normalize_user_path(rel_path, mode)
  cat = category_for_path(rel_path, mode)
  bucket = policy.bucket_for(cat)
  if bucket == BUCKET_PRIVATE:
    CREDS.resolve(repo_dir=repo_dir, require=True)
  client = s3_for_read(bucket, repo_dir)
  prefix = f"{repo}/{rel_path.rstrip('/')}/"
  logger.info(f"s3://{bucket}/{prefix}")
  s3_print_tree(s3_list_keys(client, bucket, prefix), prefix)
