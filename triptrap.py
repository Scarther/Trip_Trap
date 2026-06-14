from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path

TRAILER = b"\n<<TRIPTRAP1>>"   # marker for any-file trailer
STEGO   = b"CTK1"              # marker for image stego

G = "\033[1;32m"; R = "\033[1;31m"; Y = "\033[1;33m"; CY = "\033[1;36m"; D = "\033[2;32m"; X = "\033[0m"
def c(code: str, s: str) -> str:
    return f"{code}{s}{X}" if sys.stdout.isatty() else s

def clear() -> None:
    os.system("clear" if os.name == "posix" else "cls")

BANNER = r'''
   >>========================================<<
   || _____    _         _____               ||
   |||_   _|  (_)       |_   _|              ||
   ||  | |_ __ _ _ __     | |_ __ __ _ _ __  ||
   ||  | | '__| | '_ \    | | '__/ _` | '_ \ ||
   ||  | | |  | | |_) |   | | | | (_| | |_) |||
   ||  \_/_|  |_| .__/    \_/_|  \__,_| .__/ ||
   ||           | |                   | |    ||
   ||           |_|                   |_|    ||
   >>========================================<<'''

def banner() -> None:
    print(c(G, BANNER))
    print(c(D,  "\n      Create the wires that trip the enemy\n"))


# ── section banners ─────────────────────────────────────────
IMAGES_BANNER = r'''
+===============================+
|                __   ___  __   |
|  |  |\/|  /\  / _` |__  /__`  |
|  |  |  | /~~\ \__> |___ .__/  |
|                               |
+===============================+'''

FILES_BANNER = r'''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@                                                    @
@   ______   __     __         ______     ______     @
@  /\  ___\ /\ \   /\ \       /\  ___\   /\  ___\    @
@  \ \  __\ \ \ \  \ \ \____  \ \  __\   \ \___  \   @
@   \ \_\    \ \_\  \ \_____\  \ \_____\  \/\_____\  @
@    \/_/     \/_/   \/_____/   \/_____/   \/_____/  @
@                                                    @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'''

CHECK_BANNER = r'''
.------------------------------------------------------.
|                                                      |
|   $$$$$$\  $$\                           $$\         |
|  $$  __$$\ $$ |                          $$ |        |
|  $$ /  \__|$$$$$$$\   $$$$$$\   $$$$$$$\ $$ |  $$\   |
|  $$ |      $$  __$$\ $$  __$$\ $$  _____|$$ | $$  |  |
|  $$ |      $$ |  $$ |$$$$$$$$ |$$ /      $$$$$$  /   |
|  $$ |  $$\ $$ |  $$ |$$   ____|$$ |      $$  _$$<    |
|  \$$$$$$  |$$ |  $$ |\$$$$$$$\ \$$$$$$$\ $$ | \$$\   |
|   \______/ \__|  \__| \_______| \_______|\__|  \__|  |
|                                                      |
'------------------------------------------------------'
'''


# ── image stego (lazy PIL/numpy) ────────────────────────────
def _pil():
    try:
        import numpy as np
        from PIL import Image
        return np, Image
    except ImportError:
        return None

def _stego_payload(token: str) -> bytes:
    b = token.encode()
    return STEGO + len(b).to_bytes(4, "big") + b

def img_embed(cover: Path, token: str, out: Path) -> str:
    np, Image = _pil()
    if out.suffix.lower() in (".jpg", ".jpeg"):
        Image.open(cover).convert("RGB").save(out, format="JPEG", quality=92, comment=STEGO + token.encode())
        return "hidden in JPG comment"
    arr = np.array(Image.open(cover).convert("RGB"), dtype=np.uint8)
    flat = arr.reshape(-1)
    bits = np.unpackbits(np.frombuffer(_stego_payload(token), dtype=np.uint8))
    if bits.size > flat.size:
        raise ValueError("picture too small for that token — use a bigger image")
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(out, format="PNG")
    return "hidden in PNG pixels"

def img_extract(path: Path) -> str | None:
    pil = _pil()
    if not pil:
        return None
    np, Image = pil
    try:
        cm = Image.open(path).info.get("comment")
        if isinstance(cm, str):
            cm = cm.encode("latin-1", "ignore")
        if cm and cm.startswith(STEGO):
            return cm[len(STEGO):].decode(errors="replace")
        lsb = (np.array(Image.open(path).convert("RGB"), dtype=np.uint8).reshape(-1) & 1).astype(np.uint8)
        if lsb.size >= 64:
            head = np.packbits(lsb[:64]).tobytes()
            if head[:4] == STEGO:
                ln = int.from_bytes(head[4:8], "big")
                if 64 + ln * 8 <= lsb.size:
                    return np.packbits(lsb[64:64 + ln * 8]).tobytes().decode(errors="replace")
    except Exception:
        return None
    return None


# ── any-file trailer ────────────────────────────────────────
def file_embed(src: Path, token: str, out: Path) -> str:
    data = src.read_bytes()
    tb = token.encode()
    out.write_bytes(data + TRAILER + len(tb).to_bytes(4, "big") + tb)
    return "hidden in file trailer"

def file_extract(path: Path) -> str | None:
    data = path.read_bytes()
    i = data.rfind(TRAILER)
    if i < 0:
        return None
    off = i + len(TRAILER)
    if off + 4 > len(data):
        return None
    ln = int.from_bytes(data[off:off + 4], "big")
    if off + 4 + ln > len(data):
        return None
    return data[off + 4:off + 4 + ln].decode(errors="replace")


def extract_any(path: Path) -> str | None:
    """Check a path for a token by either method."""
    return file_extract(path) or img_extract(path)


def secure_delete(path: Path) -> None:
    try:
        n = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            fh.write(os.urandom(n)); fh.flush(); os.fsync(fh.fileno())
    except Exception:
        pass
    path.unlink(missing_ok=True)


# ── shared plant operation ──────────────────────────────────
def do_plant(src: Path, name: str, dest: Path, token: str, keep: bool, mode: str) -> int:
    if mode == "image" and not _pil():
        print(c(R, "   [-] Image traps need Pillow + numpy:  sudo apt install python3-pil python3-numpy"))
        return 2
    dest.mkdir(parents=True, exist_ok=True)
    out = (dest / name).resolve()
    src = src.resolve()
    if out.exists() and out != src:
        print(c(R, f"   [-] A file already lives there: {out}")); return 2
    try:
        how = img_embed(src, token, out) if mode == "image" else file_embed(src, token, out)
    except Exception as e:
        print(c(R, f"   [-] Could not build the trap (your file is untouched): {e}")); return 1
    if extract_any(out) != token:
        print(c(R, "   [-] Safety check FAILED — token didn't read back. Original kept."))
        if out != src:
            out.unlink(missing_ok=True)
        return 1
    os.chmod(out, 0o600)
    if out == src:
        note = "(the trap replaced your file in place)"
    elif keep:
        note = "(your original was kept)"
    else:
        secure_delete(src); note = f"(original shredded: {src})"
    print(c(G, "\n   [+] TRIP WIRE ARMED"))
    print(c(G,  f"   [+] trap file : {out}   ({how})"))
    print(c(D,  f"   [*] {note}"))
    print(c(Y,  "\n   [!] This is BAIT. Never open/share it yourself."))
    print(c(Y,  "   [!] If it's ever opened or stolen — that's your alarm."))
    rec = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} | {out} | tok:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
    print(c(CY, "\n   [*] Write this down somewhere OFF this machine:"))
    print(c(CY, f"       {rec}"))
    return 0


# ── friendly prompts ────────────────────────────────────────
def ask(prompt: str) -> str:
    return input(c(G, f"   {prompt}\n   > ")).strip().strip('"').strip("'")

def ask_existing_file(prompt: str) -> Path | None:
    while True:
        v = ask(prompt)
        if v == "":
            return None
        p = Path(v).expanduser()
        if p.is_file():
            return p
        print(c(R, "   [-] Can't find that. Try again (or blank to go back)."))

def ask_nonempty(prompt: str) -> str | None:
    while True:
        v = ask(prompt)
        if v:
            return v
        print(c(R, "   [-] Blank to go back, or type something."))
        return None


# ── menu actions ────────────────────────────────────────────
def menu_plant(mode: str) -> None:
    label = "PICTURE" if mode == "image" else "FILE"
    eg = "blueprints.jpg" if mode == "image" else "passwords.txt"
    clear()
    print(c(CY, IMAGES_BANNER if mode == "image" else FILES_BANNER))
    print()
    src = ask_existing_file(f"Step 1)  The {label.lower()} to use (drag it here or type the path):")
    if not src: return
    name = ask_nonempty(f"Step 2)  Name for the trap (example: {eg}):")
    if not name: return
    draw = ask_nonempty("Step 3)  Folder where it should live (example: ~/Documents):")
    if not draw: return
    token = ask_nonempty("Step 4)  Paste your canary token (your secret canarytokens.org link):")
    if not token: return
    print(c(D, "\n   ----- confirm -----"))
    print(c(D, f"   source : {src}"))
    print(c(D, f"   trap   : {Path(draw).expanduser() / name}"))
    print(c(D, f"   token  : {token}"))
    print(c(Y, "   The original will be SHREDDED unless you say no."))
    keep = ask("Shred the original after? (Y/n):").lower() in ("n", "no")
    if ask("Build it? (Y/n):").lower() in ("n", "no"):
        print(c(R, "   [-] Cancelled.")); return
    do_plant(src, name, Path(draw).expanduser(), token, keep, mode)

def menu_check() -> None:
    clear()
    print(c(CY, CHECK_BANNER))
    print()
    p = ask_existing_file("Which file or picture should I check?")
    if not p: return
    tok = extract_any(p)
    if tok:
        print(c(G, "\n   [+] FOUND a hidden token:")); print(c(CY, f"       {tok}"))
    else:
        print(c(Y, "\n   [-] No tripwire token in that one."))

def menu_loop() -> None:
    while True:
        clear(); banner()
        print(c(G, "      Pick Your Path:\n"))
        print(c(G, "        [1]  Hide a trip wire in a PICTURE"))
        print(c(G, "        [2]  Hide a trip wire in a FILE (any type)"))
        print(c(G, "        [3]  Check a file or picture for a trip wire"))
        print(c(G, "        [4]  Quit\n"))
        ch = input(c(G, "      > ")).strip().lower()
        if ch == "1":
            menu_plant("image")
        elif ch == "2":
            menu_plant("file")
        elif ch == "3":
            menu_check()
        elif ch in ("4", "q", "quit", "exit"):
            print(c(D, "\n      stay frosty.\n")); return
        else:
            continue
        input(c(D, "\n      press Enter to return to the menu..."))


# ── flags (README / power users) ────────────────────────────
def cmd_plant(a) -> int:
    if a.image and a.file:
        print("use either --image or --file, not both", file=sys.stderr); return 2
    src = a.image or a.file
    mode = "image" if a.image else "file"
    if not (src and a.name and a.dest and a.token):
        print("plant needs (--image|--file) --name --dest --token", file=sys.stderr); return 2
    return do_plant(Path(src).expanduser(), a.name, Path(a.dest).expanduser(), a.token, a.keep_original, mode)

def cmd_extract(a) -> int:
    tok = extract_any(Path(a.path).expanduser())
    print(tok if tok else "no canary token found")
    return 0 if tok else 1

def main() -> None:
    if len(sys.argv) == 1:
        try:
            menu_loop()
        except (KeyboardInterrupt, EOFError):
            print(c(D, "\n      stay frosty.\n"))
        return
    p = argparse.ArgumentParser(prog="triptrap", description="Trip Trap — one-stop canary tripwire shop.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("plant")
    pl.add_argument("--image"); pl.add_argument("--file"); pl.add_argument("--name")
    pl.add_argument("--dest"); pl.add_argument("--token")
    pl.add_argument("--keep-original", action="store_true")
    pl.set_defaults(func=cmd_plant)
    ex = sub.add_parser("extract"); ex.add_argument("path"); ex.set_defaults(func=cmd_extract)
    a = p.parse_args()
    sys.exit(a.func(a))


if __name__ == "__main__":
    main()
