#!/usr/bin/env python3
"""
triptrap.py — turn any file YOU made into a canary-tokened decoy.

Same idea as stego_hunt.py but for non-image files (docs, configs, keys, dumps —
whatever bait you craft). You give it your source file, a new name, where it
should live, and a canary token. It embeds the token, writes the new file,
verifies it reads back, then deletes the original so the only copy left is YOUR
tokened canary.

Embedding: a magic-delimited trailer is appended to the file end. This is
format-tolerant — text files just gain a line; many binary/document formats
(PDF, ZIP/Office, JPEG, PNG) ignore trailing bytes — so the file still opens
normally while carrying the token. Best on text/doc bait; if your viewer rejects
trailing data for an exotic format, use a text/PDF decoy instead.

Honest scope: the embedded token = ATTRIBUTION (trace a leaked copy). Alert-on-open
needs a real canarytokens.org callback token (e.g. their Word/PDF/folder token).
Nothing is written to this machine that maps your traps.

Usage (interactive — just run it):
    python3 triptrap.py

Usage (flags):
    python3 triptrap.py plant --file notes.txt --name passwords.txt \\
        --dest ~/Documents --token "https://canarytokens.com/.../submit.aspx"
    python3 triptrap.py plant ... --keep-original
    python3 triptrap.py extract suspect.txt
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path

MAGIC = b"\n<<TRIPTRAP1>>"
C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[1m", "x": "\033[0m"}


def _c(code: str, s: str) -> str:
    return f"{C[code]}{s}{C['x']}" if sys.stdout.isatty() else s


# ── embed / extract (appended trailer) ──────────────────────
def embed(src: Path, token: str, out: Path) -> None:
    data = src.read_bytes()
    tb = token.encode()
    trailer = MAGIC + len(tb).to_bytes(4, "big") + tb
    out.write_bytes(data + trailer)


def extract(path: Path) -> str | None:
    data = path.read_bytes()
    i = data.rfind(MAGIC)
    if i < 0:
        return None
    off = i + len(MAGIC)
    if off + 4 > len(data):
        return None
    ln = int.from_bytes(data[off:off + 4], "big")
    if off + 4 + ln > len(data):
        return None
    return data[off + 4:off + 4 + ln].decode(errors="replace")


# ── helpers ─────────────────────────────────────────────────
def secure_delete(path: Path) -> None:
    try:
        n = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            fh.write(os.urandom(n))
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        pass
    path.unlink(missing_ok=True)


def _ask(prompt: str, val: str | None) -> str:
    if val:
        return val
    return input(f"  {prompt}: ").strip()


# ── plant ───────────────────────────────────────────────────
def cmd_plant(args) -> int:
    print(_c("b", "\n== triptrap :: plant file canary ==\n"))
    src = Path(_ask("path to source file (the bait you made)", args.file)).expanduser()
    if not src.is_file():
        print(_c("r", f"source file not found: {src}"))
        return 2
    name = _ask("new file name (e.g. passwords.txt)", args.name)
    dest = Path(_ask("destination directory", args.dest)).expanduser()
    token = _ask("canary token (canarytokens.org URL or unique marker)", args.token)
    if not name or not token:
        print(_c("r", "name and token are required."))
        return 2

    dest.mkdir(parents=True, exist_ok=True)
    out = (dest / name).resolve()
    src = src.resolve()

    if out.exists() and out != src:
        print(_c("r", f"refusing to overwrite existing file: {out}"))
        return 2

    try:
        embed(src, token, out)
    except Exception as e:
        print(_c("r", f"embed failed (original untouched): {e}"))
        return 1

    if extract(out) != token:
        print(_c("r", "verification FAILED — token did not read back. Original kept."))
        if out != src:
            out.unlink(missing_ok=True)
        return 1
    os.chmod(out, 0o600)

    deleted = False
    if out == src:
        note = "(new file replaced the source in place)"
    elif args.keep_original:
        note = "(original kept: --keep-original)"
    else:
        secure_delete(src)
        deleted = True
        note = f"original securely deleted: {src}"

    print(_c("g", "\n  [✓] CANARY FILE CREATED"))
    print(f"      file:    {_c('b', str(out))}")
    print(f"      token:   {token}")
    print(f"      {note}")
    print(_c("y", f"\n  >>> THIS file is your canary: {out}"))
    print(_c("y", "  >>> Do NOT open it yourself. If it's ever opened/leaked, that's the alarm."))
    rec = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} | {out} | tok:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
    print(_c("b", "\n  off-box record (save this somewhere OFF this machine):"))
    print(f"    {rec}")
    if not deleted and not args.keep_original and out != src:
        print(_c("r", "  WARNING: original not deleted."))
    return 0


def cmd_extract(args) -> int:
    tok = extract(Path(args.file).expanduser())
    if tok is None:
        print("no canary token found")
        return 1
    print(tok)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="triptrap",
                                description="Turn any file into a canary-tokened decoy.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__)
    sub = p.add_subparsers(dest="cmd")
    pl = sub.add_parser("plant", help="embed token + replace original (interactive if flags omitted)")
    pl.add_argument("--file"); pl.add_argument("--name"); pl.add_argument("--dest")
    pl.add_argument("--token")
    pl.add_argument("--keep-original", action="store_true", help="do NOT delete the source file")
    pl.set_defaults(func=cmd_plant)
    ex = sub.add_parser("extract", help="recover a token from a file")
    ex.add_argument("file")
    ex.set_defaults(func=cmd_extract)

    args = p.parse_args()
    if not args.cmd:
        args = p.parse_args(["plant"])
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
