import argparse

from evc.helpers import (
  cmd_clone,
  cmd_download,
  cmd_pull,
  cmd_push,
  cmd_upload,
  cmd_view,
  bootstrap_env_creds,
)
from evc.helpers import DEFAULT_ORG, EVCError, logger


def build_parser():
  p = argparse.ArgumentParser(prog="evc", description="Ersilia Version Control (Git + S3)")
  sub = p.add_subparsers(dest="cmd", required=True)

  p_clone = sub.add_parser("clone", help="Clone repo from GitHub and fetch artifacts from S3")
  p_clone.add_argument("repo", help="Repository name (e.g., kpneumoniae-gardp)")
  p_clone.add_argument("--org", default=DEFAULT_ORG, help=f"GitHub org (default: {DEFAULT_ORG})")
  p_clone.add_argument("--dest", default=None, help="Destination folder (default: repo name)")
  p_clone.set_defaults(func=cmd_clone)

  p_pull = sub.add_parser("pull", help="git pull --rebase and refresh artifacts from S3")
  p_pull.add_argument("-y", "--yes", action="store_true", help="Assume yes for delete confirmation")
  p_pull.set_defaults(func=cmd_pull)

  p_push = sub.add_parser(
    "push", help="git push and upload artifacts to S3 (requires prior git commit)"
  )
  p_push.set_defaults(func=cmd_push)

  p_dl = sub.add_parser("download", help="Download a file/folder from S3 by relative path")
  p_dl.add_argument("--path", required=True, help="Relative path (e.g., data/processed/file.csv)")
  p_dl.set_defaults(func=cmd_download)

  p_ul = sub.add_parser("upload", help="Upload a file/folder to S3 by relative path")
  p_ul.add_argument("--path", required=True, help="Relative path (e.g., outputs/some_folder)")
  p_ul.set_defaults(func=cmd_upload)

  p_view = sub.add_parser("view", help="View S3 folder structure for a path")
  p_view.add_argument("--path", default=".", help="Relative path (e.g., data, outputs, .)")
  p_view.set_defaults(func=cmd_view)

  return p


def main():
  bootstrap_env_creds()
  parser = build_parser()
  args = parser.parse_args()
  try:
    args.func(args)
  except EVCError as e:
    logger.error(str(e))
    raise SystemExit(2)
  except KeyboardInterrupt:
    logger.error("Interrupted.")
    raise SystemExit(130)


if __name__ == "__main__":
  main()
