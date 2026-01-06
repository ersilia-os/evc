# EVC (Ersilia Version Control)

EVC is a small CLI that combines:
- **Git** for code (always on `main`)
- **S3** for large artifacts

It supports both **standard repos** (eg. ersilia-analysis-template which has data/outputs) and **model repos** (model artifacts only).

---

## What EVC stores where

### Standard repos
Artifacts are synchronized under the S3 prefix equal to the repo name:

- `data/`
- `output/`
- `model/checkpoints/` and `model/framework/fit`

So a repo named `ersilia-repo` maps to:

- `s3://<bucket>/ersilia-repo/data/...`
- `s3://<bucket>/ersilia-repo/output/...`
- `s3://<bucket>/ersilia-repo/model/<checkpoints or framework/fit>/...`

### Model repos
If the repo is a **model repo**, EVC **only** manages:

- `model/checkpoints/`
- `model/framework/`

Mapping example (`my-model-repo`):

- `s3://<bucket>/my-model-repo/model/checkpoints/...`
- `s3://<bucket>/my-model-repo/model/framework/framework/...`

In model repos, EVC refuses operations on `data/`, `output/`

---

## Buckets and access

Buckets:
- Public bucket: `evc-public`
- Private bucket: `evc-private`

Access rules intended by design:
- **Read from `evc-public` works without AWS credentials** (unsigned S3 client).
- **Write to any bucket requires AWS credentials** (env vars only).
- **Read from `evc-private` requires AWS credentials**.

> Note: For “public read without credentials” to actually work, the `evc-public` bucket policy must allow `s3:GetObject` (and if you want EVC `view` to work unauthenticated, also allow constrained `s3:ListBucket` with the expected prefixes).

---

## Installation

  ```bash
  pip install -e .
  ```
```bash
evc --help
```

---

## Credentials (env vars only)

EVC **will not** read AWS credentials from:

* `~/.aws/credentials`
* `~/.aws/config`
* `AWS_PROFILE`
* EC2 metadata

It only reads from environment variables.

### Option A (standard AWS env vars)

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
```
---

## access.json (required after clone)

EVC requires an `access.json` at the repo root for **all commands except `clone`**.

### Standard repo `access.json`

```json
{
  "data": "public",
  "output": "private"
}
```

Valid values are: `"public"` or `"private"`.

### Model repo `access.json`

```json
{
  "model": "public"
}
```

If `access.json` is missing during `clone`, EVC will do a **git-only clone** and refuse all other operations until you add `access.json`.

---

## Clone behavior with mixed access

When cloning a **standard repo**:

* If **both** `data` and `output` are `private`: EVC requires credentials.
* If **one** is private and you have **no credentials**: EVC will still proceed and download the **public** part, skipping the private part.

Examples:

* `data=public, output=private` with no creds → downloads `data/` only.
* `data=private, output=public` with no creds → downloads output dirs only.
* `data=private, output=private` with no creds → fails.

For **model repos**:

* `model=private` requires credentials.

---

## Commands

### Clone

```bash
evc clone ersilia-repo
```

Options:

```bash
evc clone ersilia-repo --org ersilia-os
evc clone ersilia-repo --dest /path/to/folder
```

### Pull (git + refresh artifacts)

```bash
cd ersilia-repo
evc pull
```

This will:

* `git pull --rebase origin/main`
* delete existing managed artifact dirs locally
* re-download from S3

Use `-y` to skip confirmation:

```bash
evc pull -y
```

### Push (requires clean git)

```bash
cd ersilia-repo
git add .
# Also you may have some data or checkpoint change which will be uploaded to S3 storage
git commit -m "Your commit message"
evc push
```

`evc push` will fail if:

* your working tree is dirty (`git status --porcelain` not empty)
* you do not have credentials in env vars

### Download a path

```bash
evc download --path data/processed/file.csv
evc download --path output/
evc download --path model/checkpoints/
```

### Upload a path (requires creds)

```bash
evc upload --path output/some_folder
evc upload --path model/checkpoints/ckpt.pt
```

### View S3 tree

```bash
evc view
evc view --path data
evc view --path model
```

---

## Access lock (no public/private migration)

EVC creates a local lock file:

* `.evc/access.lock.json`

If you later change `access.json` (e.g., `public` → `private`), EVC will refuse to run.

To override (not recommended), you must delete the lock file manually:

```bash
rm .evc/access.lock.json
```

---

## Common troubleshooting (Might be caused by policy)

### “AccessDenied” when downloading from evc-public without creds

Your bucket policy probably does not allow anonymous `ListBucket` / `GetObject` for the prefixes EVC uses.

If you want unauthenticated `download` to work:

* allow `s3:GetObject` on `arn:aws:s3:::evc-public/*`

If you want unauthenticated `view` or directory downloads to work:

* also allow `s3:ListBucket` on `arn:aws:s3:::evc-public`
* restrict it using `s3:prefix` conditions matching your repo layout

### “AWS credentials required (env vars only)”

Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (and optional session token) in your shell environment.

