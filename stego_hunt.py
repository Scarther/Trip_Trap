#!/usr/bin/env python3
"""
stego_hunt.py — turn a real image into a canary-tokened decoy.

You give it a source image, a new name, where it should live, and a canary
token. It embeds the token inside the image, writes the new file, verifies the
token reads back, then deletes the original — so the only copy left is YOUR
tokened canary. If anyone later opens/exfiltrates it you can prove (and, with a
real canarytokens.org callback token, be alerted) that it's your bait.

Embedding by output format:
  .png / .bmp   -> LSB pixel steganography (hidden in the pixels; robust)
  .jpg / .jpeg  -> JPEG comment marker (real JPEG; survives unless stripped —
                   JPEG compression would destroy LSB, so we can't use it there)

Honest scope: the hidden token = ATTRIBUTION (trace a leaked copy). Alert-on-open
only happens if the token is a real canarytokens.org callback token AND the file
format fetches it. Nothing is written to this machine that maps your traps.

Usage (interactive — just run it):
    python3 stego_hunt.py

Usage (flags):
    python3 stego_hunt.py plant --image photo.jpg --name blueprints.jpg \\
        --dest ~/Documents --token "https://canarytokens.com/.../submit.aspx"
    python3 stego_hunt.py plant ... --keep-original
    python3 stego_hunt.py extract suspect.png
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image

MAGIC = b"CTK1"
C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[1m", "x": "\033[0m"}


def _c(code: str, s: str) -> str:
    return f"{C[code]}{s}{C['x']}" if sys.stdout.isatty() else s


# ── steganography ───────────────────────────────────────────
def _payload(token: str) -> bytes:
    b = token.encode()
    return MAGIC + len(b).to_bytes(4, "big") + b


def _is_jpeg(p: Path) -> bool:
    return p.suffix.lower() in (".jpg", ".jpeg")


def lsb_embed(cover: Path, token: str, out: Path) -> None:
    arr = np.array(Image.open(cover).convert("RGB"), dtype=np.uint8)
    flat = arr.reshape(-1)
    bits = np.unpackbits(np.frombuffer(_payload(token), dtype=np.uint8))
    if bits.size > flat.size:
        raise ValueError(f"image too small: need {bits.size} bits, have {flat.size}. Use a larger image.")
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(out, format="PNG")


def lsb_extract(path: Path) -> str | None:
    lsb = (np.array(Image.open(path).convert("RGB"), dtype=np.uint8).reshape(-1) & 1).astype(np.uint8)
    if lsb.size < 64:
        return None
    head = np.packbits(lsb[:64]).tobytes()
    if head[:4] != MAGIC:
        return None
    ln = int.from_bytes(head[4:8], "big")
    if 64 + ln * 8 > lsb.size:
        return None
    return np.packbits(lsb[64:64 + ln * 8]).tobytes().decode(errors="replace")


def jpeg_embed(cover: Path, token: str, out: Path) -> None:
    Image.open(cover).convert("RGB").save(out, format="JPEG", quality=92,
                                          comment=MAGIC + token.encode())


def jpeg_extract(path: Path) -> str | None:
    c = Image.open(path).info.get("comment")
    if isinstance(c, str):
        c = c.encode("latin-1", "ignore")
    if c and c.startswith(MAGIC):
        return c[len(MAGIC):].decode(errors="replace")
    return None


def embed(cover: Path, token: str, out: Path) -> str:
    if _is_jpeg(out):
        jpeg_embed(cover, token, out)
        return "jpeg-comment"
    lsb_embed(cover, token, out)
    return "lsb-pixel"


def extract(path: Path) -> str | None:
    return lsb_extract(path) or jpeg_extract(path)


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
    print(_c("b", "\n== stego_hunt :: plant image canary ==\n"))
    src = Path(_ask("path to source image", args.image)).expanduser()
    if not src.is_file():
        print(_c("r", f"source image not found: {src}"))
        return 2
    name = _ask("new file name (e.g. blueprints.jpg)", args.name)
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

    # embed
    try:
        method = embed(src, token, out)
    except Exception as e:
        print(_c("r", f"embed failed (original untouched): {e}"))
        return 1

    # VERIFY before any deletion
    if extract(out) != token:
        print(_c("r", "verification FAILED — token did not read back. Original kept."))
        out.unlink(missing_ok=True)
        return 1
    os.chmod(out, 0o600)

    # delete original (only now that we have a verified canary)
    deleted = False
    if out == src:
        note = "(new file replaced the source in place)"
    elif args.keep_original:
        note = "(original kept: --keep-original)"
    else:
        secure_delete(src)
        deleted = True
        note = f"original securely deleted: {src}"

    print(_c("g", "\n  [✓] CANARY IMAGE CREATED"))
    print(f"      file:    {_c('b', str(out))}   ({method})")
    print(f"      token:   {token}")
    print(f"      {note}")
    print(_c("y", f"\n  >>> THIS file is your canary: {out}"))
    print(_c("y", "  >>> Do NOT open it yourself. If it's ever opened/leaked, that's the alarm."))
    # off-box record (store this in your OFFLINE notes — nothing is written to disk)
    rec = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} | {out} | tok:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
    print(_c("b", "\n  off-box record (save this somewhere OFF this machine):"))
    print(f"    {rec}")
    if not deleted and not args.keep_original and out != src:
        print(_c("r", "  WARNING: original not deleted."))
    return 0


def cmd_extract(args) -> int:
    tok = extract(Path(args.image).expanduser())
    if tok is None:
        print("no canary token found")
        return 1
    print(tok)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="stego_hunt",
                                description="Turn an image into a canary-tokened decoy.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__)
    sub = p.add_subparsers(dest="cmd")
    pl = sub.add_parser("plant", help="embed token + replace original (interactive if flags omitted)")
    pl.add_argument("--image"); pl.add_argument("--name"); pl.add_argument("--dest")
    pl.add_argument("--token")
    pl.add_argument("--keep-original", action="store_true", help="do NOT delete the source image")
    pl.set_defaults(func=cmd_plant)
    ex = sub.add_parser("extract", help="recover a token from an image")
    ex.add_argument("image")
    ex.set_defaults(func=cmd_extract)

    args = p.parse_args()
    if not args.cmd:  # bare invocation -> interactive plant wizard
        args = p.parse_args(["plant"])
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
