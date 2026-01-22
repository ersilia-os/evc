# EOSVC (Ersilia Version Control)

EOSVC is a small CLI for syncing large artifacts to **S3**, while your code remains in **Git**.

EOSVC supports two repo types (detected from `access.json`):
- **Standard repos**: manage `data/` and `output/`
- **Model repos**: manage `model/checkpoints/` and `model/eu-central-2/fit/`

EOSVC **does not** manage Git operations anymore (no clone/pull/push). Use `git` directly for code workflows.

---

## What EOSVC stores where

EOSVC syncs artifacts under an S3 prefix equal to the **repo name**.

By default, the repo name is the **local folder name** (repo directory basename).  
If your folder name differs from the remote repo/S3 prefix, set:

```bash
export EVC_REPO_NAME="my-actual-repo-name"
````

### Standard repos

Managed roots:

* `data/`
* `output/`

S3 mapping for repo `ersilia-repo`:

* `s3://<bucket>/ersilia-repo/data/...`
* `s3://<bucket>/ersilia-repo/output/...`

### Model repos

Managed roots:

* `model/checkpoints/`
* `model/fit/`

Accepted path aliases for convenience:

* `checkpoints/...` → `model/checkpoints/...`
* `fit/...` → `model/fit/...`

S3 mapping for repo `my-model-repo`:

* `s3://<bucket>/my-model-repo/model/checkpoints/...`
* `s3://<bucket>/my-model-repo/model/fit/...`

In model repos, EOSVC refuses operations on `data/` and `output/`.

---

## Buckets and access

Buckets:

* Public bucket: `eosvc-public`
* Private bucket: `eosvc-private`

Rules:

* **Read from `eosvc-public` may work without AWS credentials** (unsigned S3 client).
* **Read from `eosvc-private` requires AWS credentials**.
* **Any upload requires AWS credentials**, regardless of bucket.

> Note: For unauthenticated reads to work, the `eosvc-public` bucket policy must allow `s3:GetObject`.
> For unauthenticated `view` to work, it must also allow `s3:ListBucket` constrained to the relevant prefixes.

---

## Installation

```bash
pip install -e .
```

```bash
eosvc --help
```

---

## Credentials

EOSVC resolves credentials in this order:

1. Standard AWS resolution (environment variables and/or `~/.aws/*` if present)
2. `.env` files (loaded with `python-dotenv`) from:

   * `~/.eosvc/.env`
   * `<repo>/.env`
   * `./.env`

### Option A: environment variables (standard AWS)

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."   # optional
export AWS_REGION="eu-central-2"     # optional
```

### Option B: EOSVC config (writes ~/.eosvc/.env)

EOSVC provides a `config` command to store credentials in:

* `~/.eosvc/.env` (permissions set to `600` when possible)

```bash
eosvc config \
  --access-key-id "..." \
  --secret-access-key "..." \
  --session-token "..." \
  --region "eu-central-2"
```

This is similar in spirit to `aws configure`, but EOSVC writes a `.env` file and loads it alongside other sources.

### Option C: local .env files

Create `.env` in the repo (or current directory):

```bash
AWS_ACCESS_KEY_ID="..."
AWS_SECRET_ACCESS_KEY="..."
AWS_SESSION_TOKEN="..."   # optional
AWS_REGION="eu-central-2"    # optional
```

---

## access.json (required)

EOSVC requires an `access.json` at the repo root.
EOSVC identifies the repo root by searching upward for `access.json` starting from the current directory.

### Standard repo `access.json`

```json
{
  "data": "public",
  "output": "private"
}
```

### Model repo `access.json`

```json
{
  "checkpoints": "public",
  "fit": "public"
}
```

Valid values are: `"public"` or `"private"`.

---

## Commands

### config

Write AWS credentials to `~/.eosvc/.env`:

```bash
eosvc config --access-key-id "..." --secret-access-key "..."
```

Optional flags:

```bash
eosvc config \
  --access-key-id "..." \
  --secret-access-key "..." \
  --session-token "..." \
  --region "eu-central-2" \
  --default-region "eu-central-2"
```

### view (S3 tree)

View the artifact layout in S3:

```bash
eosvc view
eosvc view --path data
eosvc view --path output
eosvc view --path model/checkpoints
eosvc view --path checkpoints
eosvc view --path fit
```

### download

Download a file or folder from S3 into your repo:

```bash
eosvc download --path data/processed/file.csv
eosvc download --path output/
eosvc download --path model/checkpoints/
eosvc download --path checkpoints/
eosvc download --path fit/
```

### upload

Upload a file or folder to S3 (requires credentials):

```bash
eosvc upload --path output/some_folder
eosvc upload --path data/test
eosvc upload --path model/checkpoints/test-run
eosvc upload --path checkpoints/test-run
eosvc upload --path fit/test-fit
```

---

## Quick Test

From the project root:

```bash
cd tests
chmod +x test.sh
./test.sh
```

The test script:

* uses `git clone` to obtain test repos
* runs `view`, `upload`, and `download` for both model and standard repos

---

## Access lock (no public/private migration)

EOSVC creates a local lock file:

* `.evc/access.lock.json`

If you later change `access.json` (e.g., `public` → `private`), EOSVC will refuse to run.

To override (not recommended), delete the lock file manually:

```bash
rm .evc/access.lock.json
```

---

## Common troubleshooting

### “AccessDenied” when reading eosvc-public without creds

Your bucket policy probably does not allow anonymous access for the prefixes EOSVC uses.

If you want unauthenticated `download` to work:

* allow `s3:GetObject` on `arn:aws:s3:::eosvc-public/*`

If you want unauthenticated `view` to work:

* also allow `s3:ListBucket` on `arn:aws:s3:::eosvc-public`
* restrict with `s3:prefix` conditions for your repo prefixes

### “AWS credentials are missing or invalid”

Provide credentials via:

* env vars, or
* `eosvc config` (writes `~/.eosvc/.env`), or
* a `.env` file in the repo/current directory

---

## About the Ersilia Open Source Initiative

The [Ersilia Open Source Initiative](https://ersilia.io) is a tech-nonprofit organization fueling sustainable research in the Global South. Ersilia's main asset is the [Ersilia Model Hub](https://github.com/ersilia-os/ersilia), an open-source repository of AI/ML models for antimicrobial drug discovery.

![Ersilia Logo](assets/Ersilia_Brand.png)
