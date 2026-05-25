#!/usr/bin/env python3
import os
import sys
from pathlib import Path


APP_USER = os.getenv("APP_USER", "appuser")
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", DATA_DIR / "uploads"))


def chown_tree(path: Path, uid: int, gid: int) -> None:
    if not path.exists():
        return
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for name in dirs:
            os.chown(Path(root) / name, uid, gid)
        for name in files:
            os.chown(Path(root) / name, uid, gid)


def main() -> None:
    command = sys.argv[1:] or ["python", "app.py"]
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        import pwd

        user = pwd.getpwnam(APP_USER)
        chown_tree(DATA_DIR, user.pw_uid, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)

    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
