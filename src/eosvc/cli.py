import argparse

from eosvc.helpers import cmd_config, cmd_download, cmd_upload, cmd_view
from eosvc.helpers import EOSVCError, logger


def build_parser():
  p = argparse.ArgumentParser(prog="eosvc", description="Ersilia Version Control (S3)")
  sub = p.add_subparsers(dest="cmd", required=True)

  p_cfg = sub.add_parser("config", help="Write AWS credentials to ~/.eosvc/.env")
  p_cfg.add_argument("--access-key-id", required=True)
  p_cfg.add_argument("--secret-access-key", required=True)
  p_cfg.add_argument("--session-token", default=None)
  p_cfg.add_argument("--region", default=None)
  p_cfg.add_argument("--default-region", default=None)
  p_cfg.set_defaults(func=cmd_config)

  p_dl = sub.add_parser("download", help="Download a file/folder from S3 by relative path")
  p_dl.add_argument("--path", required=True)
  p_dl.set_defaults(func=cmd_download)

  p_ul = sub.add_parser("upload", help="Upload a file/folder to S3 by relative path")
  p_ul.add_argument("--path", required=True)
  p_ul.set_defaults(func=cmd_upload)

  p_view = sub.add_parser("view", help="View S3 folder structure for a path")
  p_view.add_argument("--path", default=".")
  p_view.set_defaults(func=cmd_view)

  return p


def main():
  parser = build_parser()
  args = parser.parse_args()
  try:
    args.func(args)
  except EOSVCError as e:
    logger.error(str(e))
    raise SystemExit(2)
  except KeyboardInterrupt:
    logger.error("Interrupted.")
    raise SystemExit(130)


if __name__ == "__main__":
  main()
