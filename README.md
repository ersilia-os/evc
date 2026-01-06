# EOSVC (Ersilia Version Control)

EOSVC is a small CLI that combines:
- **Git** for code (always on `main`)
- **S3** for large artifacts

It supports both **standard repos** (eg. ersilia-analysis-template which has data/outputs) and **model repos** (model artifacts only).

---

## What EOSVC stores where

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
If the repo is a **model repo**, EOSVC **only** manages:

- `model/checkpoints/`
- `model/framework/`

Mapping example (`my-model-repo`):

- `s3://<bucket>/my-model-repo/model/checkpoints/...`
- `s3://<bucket>/my-model-repo/model/framework/git/...`

In model repos, EOSVC refuses operations on `data/`, `output/`

---

## Buckets and access

Buckets:
- Public bucket: `eosvc-public`
- Private bucket: `eosvc-private`

Access rules intended by design:
- **Read from `eosvc-public` works without AWS credentials** (unsigned S3 client).
- **Write to any bucket requires AWS credentials** (env vars only).
- **Read from `eosvc-private` requires AWS credentials**.

> Note: For “public read without credentials” to actually work, the `eosvc-public` bucket policy must allow `s3:GetObject` (and if you want EOSVC `view` to work unauthenticated, also allow constrained `s3:ListBucket` with the expected prefixes).

---

## Installation

  ```bash
  pip install -e .
  ```
```bash
eosvc --help
```

---

## Credentials (env vars only)

EOSVC **will ** read AWS credentials from:

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
### Option B (standard AWS env vars in .env file)

```bash
#.env
AWS_ACCESS_KEY_ID="..."
AWS_SECRET_ACCESS_KEY="..."
```

---

## access.json (required after clone)

EOSVC requires an `access.json` at the repo root for **all commands except `clone`**.

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
  "checkpoints": "public",
  "framework": "public" # fit folder is abstracted
}
```

If `access.json` is missing during `clone`, EOSVC will do a **git-only clone** and refuse all other operations until you add `access.json`.

---

## Clone behavior with mixed access

When cloning a **standard repo**:

* If **both** `data` and `output` are `private`: EOSVC requires credentials.
* If **one** is private and you have **no credentials**: EOSVC will still proceed and download the **public** part, skipping the private part.

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
eosvc clone ersilia-repo
```

Options:

```bash
eosvc clone ersilia-repo --org ersilia-os
eosvc clone ersilia-repo --dest /path/to/folder
```

### Pull (git + refresh artifacts)

```bash
cd ersilia-repo
eosvc pull
```

This will:

* `git pull --rebase origin/main`
* delete existing managed artifact dirs locally
* re-download from S3

Use `-y` to skip confirmation:

```bash
eosvc pull -y
```

### Push (requires clean git)

```bash
cd ersilia-repo
git add .
# Also you may have some data or checkpoint change which will be uploaded to S3 storage
git commit -m "Your commit message"
eosvc push
```

`eosvc push` will fail if:

* your working tree is dirty (`git status --porcelain` not empty)
* you do not have credentials in env vars

### Download a path

```bash
eosvc download --path data/processed/file.csv
eosvc download --path output/
eosvc download --path model/checkpoints/
```

### Upload a path (requires creds)

```bash
eosvc upload --path output/some_folder
eosvc upload --path model/checkpoints/ckpt.pt
```

### View S3 tree

```bash
eosvc view
eosvc view --path data
eosvc view --path model
```

### Quick Test
- Set the env variable values and
```bash
cd tests
chmod +x test.sh
./test.sh
```
---

## Access lock (no public/private migration)

EOSVC creates a local lock file:

* `.eosvc/access.lock.json`

If you later change `access.json` (e.g., `public` → `private`), EOSVC will refuse to run.

To override (not recommended), you must delete the lock file manually:

```bash
rm .eosvc/access.lock.json
```

---

## Common troubleshooting (Might be caused by policy)

### “AccessDenied” when downloading from eosvc-public without creds

Your bucket policy probably does not allow anonymous `ListBucket` / `GetObject` for the prefixes EOSVC uses.

If you want unauthenticated `download` to work:

* allow `s3:GetObject` on `arn:aws:s3:::eosvc-public/*`

If you want unauthenticated `view` or directory downloads to work:

* also allow `s3:ListBucket` on `arn:aws:s3:::eosvc-public`
* restrict it using `s3:prefix` conditions matching your repo layout

### “AWS credentials required (env vars only)”

Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (and optional session token) in your shell environment.



## About the Ersilia Open Source Initiative

The [Ersilia Open Source Initiative](https://ersilia.io) is a tech-nonprofit organization fueling sustainable research in the Global South. Ersilia's main asset is the [Ersilia Model Hub](https://github.com/ersilia-os/ersilia), an open-source repository of AI/ML models for antimicrobial drug discovery.

![Ersilia Logo](assets/Ersilia_Brand.png)
