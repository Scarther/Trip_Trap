#!/usr/bin/env python3
"""
triptrap.py — plug-and-play tripwires for your computer or burner phone. Plant
bait files that buzz your phone when someone snoops, and tag files so you can
prove a leak. Self-hosted, self-contained, self-wiping. One person, one script.

NEW? Just run it:  python3 triptrap.py   then type  ABOUT  for a plain-English tour.

MENU
  1) TRIPWIRE Creation   alerting bait — pings your phone (ntfy)
       a) Alerting document (Word/SVG/HTML)  — fires on OPEN, needs catcher+listener
       b) Watch a file/folder (fontcache)    — fires on access; Linux/Android/Windows;
                                                pushes ntfy DIRECTLY (no catcher needed)
  2) TRACE Creation      mark a file/picture so a leaked copy is provably yours (no alert)
  3) CHECK files         scan files/images for an embedded ntfy token (forensics)
  4) WIPE                shred the tool's footprint + watcher, optional self-destruct
  5) Quit

Type any CAPS word (ABOUT / TRIPWIRE / TRACE / CHECK / WIPE) at the menu for details.
"""
from __future__ import annotations

import json
import os
import platform
import random
import re
import secrets
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

CFG_DIR = Path.home() / ".triptrap"
CFG = CFG_DIR / "config.json"
DB = CFG_DIR / "canaries.jsonl"
HITS = CFG_DIR / "hits.log"
NTFY_SRV = "https://ntfy.sh"

TRAILER = b"\n<<TRIPTRAP1>>"
STEGO = b"CTK1"
WATCHER_NAME = "fontcache"   # inconspicuous on-disk name for the watcher

# Flat types a callback token CANNOT be embedded in -> these go the TRACE route.
FLAT_EXTS = {".txt", ".csv", ".log", ".json", ".md", ".cfg", ".ini", ".conf",
             ".dat", ".bin", ".png", ".jpg", ".jpeg", ".bmp", ".gif"}

G="\033[1;32m"; R="\033[1;31m"; Y="\033[1;33m"; CY="\033[1;36m"; D="\033[2;32m"; X="\033[0m"
def c(code, s): return f"{code}{s}{X}" if sys.stdout.isatty() else s
def clear(): os.system("clear" if os.name == "posix" else "cls")

def is_android() -> bool:
    return os.path.exists("/system/bin/getprop") or "ANDROID_ROOT" in os.environ
def local_os() -> str:
    if is_android(): return "android"
    return "windows" if os.name == "nt" else "linux"

TITLE = r'''
      ______     _     ______
     /_  __/____(_)___/_  __/________ _____
      / / / ___/ / __ \/ / / ___/ __ `/ __ \
     / / / /  / / /_/ / / / /  / /_/ / /_/ /
    /_/ /_/  /_/ .___/_/ /_/   \__,_/ .___/
              /_/                  /_/'''

TAGLINES = [
    "the wires that trip the enemy",
    "they open it. you know.",
    "bait. watch. trace. burn.",
    "every file a landmine",
    "trust nothing. tag everything.",
    "silent alarms for loud intruders",
]

SEC = {
"TRIPWIRE": r'''
+==========================================+
|  _____ ___ ___ _____      _____ ___ ___  |
| |_   _| _ \_ _| _ \ \    / /_ _| _ \ __| |
|   | | |   /| ||  _/\ \/\/ / | ||   / _|  |
|   |_| |_|_\___|_|   \_/\_/ |___|_|_\___| |
+==========================================+''',
"TRACE": r'''
+============================+
|  _____ ___    _   ___ ___  |
| |_   _| _ \  /_\ / __| __| |
|   | | |   / / _ \ (__| _|  |
|   |_| |_|_\/_/ \_\___|___| |
+============================+''',
"CHECK": r'''
+==========================+
|   ___ _  _ ___ ___ _  __ |
|  / __| || | __/ __| |/ / |
| | (__| __ | _| (__| ' <  |
|  \___|_||_|___\___|_|\_\ |
+==========================+''',
"WIPE": r'''
+========================+
| __      _____ ___ ___  |
| \ \    / /_ _| _ \ __| |
|  \ \/\/ / | ||  _/ _|  |
|   \_/\_/ |___|_| |___| |
+========================+''',
}

def block(s, color=CY):
    for ln in s.strip("\n").split("\n"): print(c(color, "   " + ln))

def tip(*lines):
    """Plain-English 'what this does' guidance shown at the top of a section."""
    for l in lines: print(c(D, "   " + l))
    print()

def banner():
    print(c(G, TITLE))
    print(c(CY, "   ::" + "=" * 44 + "::"))
    print(c(Y,  "     >> " + random.choice(TAGLINES)))
    print(c(CY, "   ::" + "=" * 44 + "::"))
    print(c(D,  "      self-hosted canary kit  ·  bait · watch · trace\n"))


# ── config / db ─────────────────────────────────────────────
def load_cfg():
    try: return json.loads(CFG.read_text()) if CFG.exists() else {}
    except Exception: return {}
def save_cfg(cfg):
    CFG_DIR.mkdir(exist_ok=True); CFG.write_text(json.dumps(cfg, indent=2)); os.chmod(CFG, 0o600)
def db_add(rec):
    CFG_DIR.mkdir(exist_ok=True)
    with open(DB, "a") as fh: fh.write(json.dumps(rec) + "\n")
def db_all():
    return [json.loads(l) for l in DB.read_text().splitlines() if l.strip()] if DB.exists() else []


# ── TRACE: stego (images) + trailer (any file) ──────────────
# Obfuscated marker: a NON-PRINTABLE magic + XOR'd token, so `strings`/`tail`
# reveal nothing readable. Old plaintext markers (TRAILER/STEGO) are still READ
# for backward-compat, but never written anymore.
OBF_MAGIC = b"\x9f\x2c\x06\xe1\x57\xba\x11"          # invalid UTF-8 -> invisible to `strings`
OBF_KEY = b"\x5a\xa5\x3c\xc3\x69\x96\x0f\xf0\x21\xde"
def _xor(b): return bytes(x ^ OBF_KEY[i % len(OBF_KEY)] for i, x in enumerate(b))
def _pack(token):
    tb = _xor(token.encode())
    return OBF_MAGIC + len(tb).to_bytes(4, "big") + tb
def _unpack(data):
    i = data.rfind(OBF_MAGIC)
    if i < 0: return None
    off = i + len(OBF_MAGIC)
    if off + 4 > len(data): return None
    ln = int.from_bytes(data[off:off + 4], "big")
    if off + 4 + ln > len(data): return None
    return _xor(data[off + 4:off + 4 + ln]).decode(errors="replace")

def _pil():
    try:
        import numpy as np
        from PIL import Image
        return np, Image
    except ImportError:
        return None
def img_embed(cover, token, out):
    np, Image = _pil()
    pay = _pack(token)
    if out.suffix.lower() in (".jpg", ".jpeg"):
        Image.open(cover).convert("RGB").save(out, "JPEG", quality=92, comment=pay)
        return "hidden in JPG comment"
    arr = np.array(Image.open(cover).convert("RGB"), dtype=np.uint8); flat = arr.reshape(-1)
    bits = np.unpackbits(np.frombuffer(pay, dtype=np.uint8))
    if bits.size > flat.size: raise ValueError("picture too small — use a bigger image")
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(out, "PNG"); return "hidden in PNG pixels"
def img_extract(path):
    pil = _pil()
    if not pil: return None
    np, Image = pil
    HB = len(OBF_MAGIC) + 4
    try:
        cm = Image.open(path).info.get("comment")
        if isinstance(cm, str): cm = cm.encode("latin-1", "ignore")
        if cm:
            t = _unpack(cm)
            if t is not None: return t
            if cm.startswith(STEGO): return cm[len(STEGO):].decode(errors="replace")  # legacy
        flat = (np.array(Image.open(path).convert("RGB"), dtype=np.uint8).reshape(-1) & 1).astype(np.uint8)
        if flat.size >= HB * 8:
            head = np.packbits(flat[:HB * 8]).tobytes()
            if head[:len(OBF_MAGIC)] == OBF_MAGIC:
                ln = int.from_bytes(head[len(OBF_MAGIC):HB], "big")
                tot = (HB + ln) * 8
                if tot <= flat.size: return _xor(np.packbits(flat[HB * 8:tot]).tobytes()).decode(errors="replace")
            if head[:4] == STEGO:  # legacy
                ln = int.from_bytes(head[4:8], "big")
                if 64 + ln * 8 <= flat.size: return np.packbits(flat[64:64 + ln * 8]).tobytes().decode(errors="replace")
    except Exception: return None
    return None
def file_embed(src, token, out):
    out.write_bytes(src.read_bytes() + _pack(token)); return "hidden in file trailer"
def file_extract(path):
    data = path.read_bytes()
    t = _unpack(data)
    if t is not None: return t
    i = data.rfind(TRAILER)                              # legacy plaintext
    if i < 0: return None
    off = i + len(TRAILER)
    if off + 4 > len(data): return None
    ln = int.from_bytes(data[off:off + 4], "big")
    return data[off + 4:off + 4 + ln].decode(errors="replace") if off + 4 + ln <= len(data) else None
def extract_any(path): return file_extract(path) or img_extract(path)
def secure_delete(path):
    try:
        n = Path(path).stat().st_size
        with open(path, "r+b", buffering=0) as fh: fh.write(os.urandom(n)); fh.flush(); os.fsync(fh.fileno())
    except Exception: pass
    Path(path).unlink(missing_ok=True)


# ── TRIPWIRE docs (callback on open) + listener ─────────────
def make_svg(url, out):
    out.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" width="600" height="400">\n<rect width="600" height="400" fill="#10243a"/>\n'
        f'<image xlink:href="{url}" x="0" y="0" width="1" height="1"/>\n'
        '<text x="40" y="210" fill="#9fb8d6" font-family="monospace" font-size="20">CONFIDENTIAL</text>\n</svg>\n')
def make_html(url, out):
    out.write_text("<!doctype html><html><head><meta charset='utf-8'><title>Confidential</title></head>\n"
        f"<body><h3>Confidential — do not distribute</h3><img src=\"{url}\" width=1 height=1 alt=\"\"></body></html>\n")
def make_docx(url, out, title="Confidential"):
    NS = "http://schemas.openxmlformats.org/"
    f = {
     "[Content_Types].xml":'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/></Types>',
     "_rels/.rels":f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{NS}officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
     "word/document.xml":f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{title} — internal only.</w:t></w:r></w:p></w:body></w:document>',
     "word/_rels/document.xml.rels":f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{NS}officeDocument/2006/relationships/settings" Target="settings.xml"/></Relationships>',
     "word/settings.xml":'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:attachedTemplate r:id="rId1"/></w:settings>',
     "word/_rels/settings.xml.rels":f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{NS}officeDocument/2006/relationships/attachedTemplate" Target="{url}" TargetMode="External"/></Relationships>',
    }
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in f.items(): z.writestr(n, d)

def push_ntfy(topic, msg):
    try:
        urllib.request.urlopen(urllib.request.Request(f"{NTFY_SRV}/{topic}", data=msg.encode(),
            headers={"Title": "CANARY TRIPPED", "Priority": "high", "Tags": "rotating_light"}), timeout=8).read()
        return True
    except Exception as e:
        print(c(R, f"   [-] ntfy push failed: {e}")); return False
def _label_for(tid):
    for r in db_all():
        if r["id"] == tid: return r.get("label", tid)
    return tid
class Handler(BaseHTTPRequestHandler):
    cfg = {}
    def log_message(self, *a): pass
    def _hit(self):
        tid = self.path.strip("/").split("/")[0].split(".")[0] or "?"
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]); ua = self.headers.get("User-Agent", "?")
        ts = time.strftime("%Y-%m-%dT%H:%M:%S"); lab = _label_for(tid)
        line = f"[{ts}] TRIPPED id={tid} label={lab!r} ip={ip} ua={ua!r}"
        CFG_DIR.mkdir(exist_ok=True)
        with open(HITS, "a") as fh: fh.write(line + "\n")
        print(c(R, "   " + line))
        if self.cfg.get("ntfy_topic"): push_ntfy(self.cfg["ntfy_topic"], f"{lab} opened — {ip} ({ts})")
        gif = bytes.fromhex("47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b")
        self.send_response(200); self.send_header("Content-Type", "image/gif"); self.end_headers(); self.wfile.write(gif)
    def do_GET(self): self._hit()
    def do_HEAD(self): self._hit()
def serve(port):
    cfg = load_cfg(); Handler.cfg = cfg
    print(c(G, f"\n   [*] listener on 0.0.0.0:{port}  ->  ntfy: {cfg.get('ntfy_topic','(set in TRIPWIRE)')}"))
    print(c(D, "   [*] point your catcher (tunnel/VPS) here. Ctrl-C to stop.\n"))
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


# ── WATCHER templates (fontcache) — autonomous, push ntfy directly ──
FC_LINUX = r'''#!/usr/bin/env python3
# fontcache — file-access monitor (stdlib only). Pushes ntfy on watched-path access.
import ctypes, ctypes.util, os, struct, sys, time, urllib.request
TOPIC="__TOPIC__"; SRV="__SRV__"
WATCH=[p for p in r"__WATCH__".split("|") if p]
M_FILE=0x1|0x20|0x2|0x40|0x200
M_DIR=0x100|0x80|0x200
def notify(m):
    try: urllib.request.urlopen(urllib.request.Request(SRV+"/"+TOPIC,data=m.encode(),headers={"Title":"fontcache","Priority":"high","Tags":"warning"}),timeout=8)
    except Exception: pass
libc=ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",use_errno=True)
fd=libc.inotify_init(); wd={}; wd_dirs=set()
for p in WATCH:
    p=os.path.expanduser(p).rstrip("/")
    if os.path.exists(p):
        is_dir=os.path.isdir(p)
        w=libc.inotify_add_watch(fd,p.encode(),M_DIR if is_dir else M_FILE)
        if w>=0: wd[w]=p; (wd_dirs.add(w) if is_dir else None)
if not wd: sys.exit(0)
SZ=struct.calcsize("iIII")
while True:
    b=os.read(fd,4096); i=0
    while i<len(b):
        w,mask,ck,nl=struct.unpack_from("iIII",b,i); i+=SZ
        nm=b[i:i+nl].split(b"\x00",1)[0].decode("utf-8","replace"); i+=nl
        base=wd.get(w,"?"); full=os.path.join(base,nm) if nm else base
        verb="created" if w in wd_dirs else "opened"
        notify(verb+": "+full+" ("+time.strftime("%F %T")+")"); time.sleep(2)
'''
FC_ANDROID = r'''#!/system/bin/sh
# fontcache — file-access monitor (Android toybox inotifyd). No deps.
TOPIC="__TOPIC__"; SRV="__SRV__"
send(){ curl -s -m8 -H "Title: fontcache" -H "Priority: high" -d "$1" "$SRV/$TOPIC" >/dev/null 2>&1 \
  || wget -q -O- --post-data="$1" "$SRV/$TOPIC" >/dev/null 2>&1 \
  || busybox wget -q -O- --post-data="$1" "$SRV/$TOPIC" >/dev/null 2>&1; }
if [ -n "$2" ]; then send "opened: $2$3 ($(date '+%F %T'))"; exit 0; fi
S="$0"; set --
for t in __WATCH__; do [ -e "$t" ] && set -- "$@" "$t"; done
[ $# -eq 0 ] && exit 0
exec inotifyd "$S" "$@"
'''
FC_WINDOWS = r'''# fontcache.ps1 — file monitor (Windows). Alerts ntfy on change/create/delete/rename.
# NOTE: Windows can't see read-only opens via FileSystemWatcher (catches writes/moves/deletes).
# Run hidden + persist:  powershell -ExecutionPolicy Bypass -File fontcache.ps1 -Install
param([switch]$Install)
$Topic="__TOPIC__"; $Srv="__SRV__"; $Paths=@(__WATCH__)
if($Install){
  $a="-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
  schtasks /Create /SC ONLOGON /TN "fontcache" /TR "powershell $a" /F | Out-Null
  Start-Process powershell -ArgumentList $a -WindowStyle Hidden; return }
function Send($m){ try{ Invoke-RestMethod -Uri "$Srv/$Topic" -Method Post -Body $m -Headers @{Title="fontcache";Priority="high"} -TimeoutSec 8 }catch{} }
$ws=@()
foreach($p in $Paths){ if(Test-Path $p){
  $it=Get-Item $p
  if($it.PSIsContainer){$dir=$p;$fil="*"} else {$dir=Split-Path $p;$fil=Split-Path $p -Leaf}
  $w=New-Object IO.FileSystemWatcher $dir,$fil; $w.EnableRaisingEvents=$true
  Register-ObjectEvent $w Changed -Action { Send("changed: $($Event.SourceEventArgs.FullPath) ($(Get-Date -f s))") } | Out-Null
  Register-ObjectEvent $w Deleted -Action { Send("deleted: $($Event.SourceEventArgs.FullPath) ($(Get-Date -f s))") } | Out-Null
  Register-ObjectEvent $w Renamed -Action { Send("renamed: $($Event.SourceEventArgs.FullPath) ($(Get-Date -f s))") } | Out-Null
  $ws+=$w } }
if($ws.Count -eq 0){ exit }
while($true){ Start-Sleep 3600 }
'''

# Standalone watcher files shipped alongside triptrap.py in the repo. If present
# next to this script we use them (so a git clone uses the real files); otherwise
# we fall back to the embedded template (so a lone triptrap.py still works).
WATCH_FILES = {"linux": "fontcache_linux.py", "android": "fontcache_android.sh", "windows": "fontcache_windows.ps1"}
EMBEDDED = {"linux": FC_LINUX, "android": FC_ANDROID, "windows": FC_WINDOWS}

def _raw_template(target_os):
    p = Path(__file__).resolve().parent / WATCH_FILES[target_os]
    try:
        if p.exists():
            return p.read_text()
    except Exception:
        pass
    return EMBEDDED[target_os]

def build_watcher(target_os, topic, paths):
    """Return (filename, text) for the chosen OS with token+paths baked in.
    Uses the repo's fontcache_<os> file if present, else the embedded template."""
    raw = _raw_template(target_os)
    if target_os == "linux":
        t = raw.replace("__TOPIC__", topic).replace("__SRV__", NTFY_SRV).replace("__WATCH__", "|".join(paths))
        return WATCHER_NAME, t
    if target_os == "android":
        t = raw.replace("__TOPIC__", topic).replace("__SRV__", NTFY_SRV).replace("__WATCH__", " ".join(f'"{p}"' for p in paths))
        return WATCHER_NAME + ".sh", t
    if target_os == "windows":
        arr = ",".join('"' + p.replace("\\", "\\\\") + '"' for p in paths)
        t = raw.replace("__TOPIC__", topic).replace("__SRV__", NTFY_SRV).replace("__WATCH__", arr)
        return WATCHER_NAME + ".ps1", t
    raise ValueError(target_os)

def install_watcher_local(text) -> str:
    """Install + start the watcher on THIS machine (linux/android). Returns note."""
    osn = local_os()
    if osn == "linux":
        d = Path.home() / ".config" / WATCHER_NAME
        d.mkdir(parents=True, exist_ok=True)
        wp = d / WATCHER_NAME
        wp.write_text(text); os.chmod(wp, 0o755)
        # systemd --user unit
        ud = Path.home() / ".config" / "systemd" / "user"; ud.mkdir(parents=True, exist_ok=True)
        (ud / f"{WATCHER_NAME}.service").write_text(
            f"[Unit]\nDescription=font cache index\n[Service]\nExecStart={sys.executable} {wp}\nRestart=always\n[Install]\nWantedBy=default.target\n")
        for cmd in (["systemctl","--user","daemon-reload"],
                    ["systemctl","--user","enable",f"{WATCHER_NAME}.service"],
                    ["systemctl","--user","restart",f"{WATCHER_NAME}.service"]):
            subprocess.run(cmd, capture_output=True)
        return f"installed + restarted (systemd --user: {WATCHER_NAME}.service)"
    if osn == "android":
        wp = Path(f"/data/adb/service.d/{WATCHER_NAME}.sh")
        try:
            tmp = Path("/sdcard") / f"{WATCHER_NAME}.sh"; tmp.write_text(text)
            subprocess.run(["su","-c",f"cp {tmp} {wp} && chmod 755 {wp} && sh {wp} &"], capture_output=True)
            tmp.unlink(missing_ok=True)
            return f"installed (Magisk service.d: {wp}) + started"
        except Exception as e:
            return f"write the file to /data/adb/service.d/ manually ({e})"
    return "this machine isn't the target — file written for you to deploy"

def deploy_local_watch(topic, new_paths) -> str:
    """Merge new_paths into the persistent watch list, rebuild + reinstall the
    local fontcache watcher so it covers ALL watched paths."""
    cfg = load_cfg()
    wp = cfg.get("watch_paths", [])
    for p in new_paths:
        if p not in wp: wp.append(p)
    cfg["watch_paths"] = wp; save_cfg(cfg)
    _, text = build_watcher(local_os(), topic, wp)
    return install_watcher_local(text)

def remove_watcher_local():
    osn = local_os()
    if osn == "linux":
        subprocess.run(["systemctl","--user","disable","--now",f"{WATCHER_NAME}.service"], capture_output=True)
        (Path.home()/".config"/"systemd"/"user"/f"{WATCHER_NAME}.service").unlink(missing_ok=True)
        shutil.rmtree(Path.home()/".config"/WATCHER_NAME, ignore_errors=True)
    elif osn == "android":
        subprocess.run(["su","-c",f"rm -f /data/adb/service.d/{WATCHER_NAME}.sh; pkill -f {WATCHER_NAME}"], capture_output=True)


# ── Windows folder/shortcut token (browse-fires; needs DNS/SMB catcher) ──
def make_win_folder_token(host, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "desktop.ini").write_text(
        "[.ShellClassInfo]\n" f"IconResource=\\\\{host}\\share\\x.ico,0\n", encoding="utf-8")
    (outdir / "Open me.scf").write_text(
        "[Shell]\nCommand=2\nIconFile=" f"\\\\{host}\\share\\y.ico\n[Taskbar]\nCommand=ToggleDesktop\n", encoding="utf-8")


# ── help texts ──────────────────────────────────────────────
HELP = {
"ABOUT": """WHAT IS THIS? Trip Trap plants bait files that tell you when someone
  snoops your computer or burner phone. Out-of-the-box, nothing to rent or host.

  THE WORDS (plain English):
   - TRIPWIRE  = a bait file that ALERTS you (buzzes your phone) when it's opened.
   - TRACE     = stamp a hidden MARKER inside a file. No alert by itself — but if
                 that file ever leaks, you prove it was YOUR copy by finding the marker.
   - MARKER    = a secret word YOU pick (e.g. blue-falcon-77). It's hidden inside the
                 file; nobody sees it. You read it back later with CHECK.
   - ntfy TOKEN= a secret channel name your phone listens on. Install the free 'ntfy'
                 app, subscribe to your token, and trips buzz your phone instantly.
   - fontcache = the quiet watcher that sits on the machine and sends the buzz when a
                 watched file is opened. (Deliberately boring name so it blends in.)
   - CATCHER   = (advanced) a web address that catches 'document' traps opened on
                 OTHER people's machines. NOT needed to watch your own files.

  EASIEST START (90 seconds):
   1) Menu -> 2 (TRACE) -> 1 (create) -> name it 'logins.txt', pick a marker word.
   2) Say YES to 'also WATCH this' -> it generates your ntfy token + shows the URL.
   3) Phone: open the ntfy app -> [+] -> paste that token -> Subscribe.
   4) Open logins.txt -> your phone buzzes. Done.
   5) WIPE erases everything when you're finished.""",
"TRIPWIRE": """TRIPWIRE — bait that ALERTS you when touched.
  Two kinds:
   a) Alerting document (Word/SVG/HTML): the file fetches a hidden URL the moment
      it's OPENED -> your listener catches it -> ntfy buzzes your phone. Works on any
      OS that opens it, even on someone else's machine. Needs a public 'catcher'
      (a VPS domain or a Cloudflare Tunnel) running the listener.
   b) Watch a file/folder (fontcache): a tiny monitor sits on the machine and pings
      ntfy the instant a watched file/folder is opened. Perfect for .txt and other
      flat files that can't phone home themselves. NO catcher needed — it pushes
      ntfy directly. Pick the target OS (Linux / Android / Windows); it bakes your
      token in, drops a boring-named watcher ('fontcache'), and starts it.
  ntfy step: you get a secret topic (generated or your own). Install the ntfy app,
  subscribe to that topic, and every trip buzzes your phone. Full URL is shown so you
  paste it straight into the app.""",
"TRACE": """TRACE — for files a CALLBACK TOKEN CANNOT be embedded in (flat files).
  A .txt, .csv, .log, .json, .md, .cfg, raw binaries, and standalone images can't
  fetch a URL when opened, so they can't alert on their own (physics). TRACE instead
  hides a marker inside (PNG -> pixels, JPG -> comment, any other file -> invisible
  trailer), shreds the original, and leaves only the tagged copy. If it leaks and you
  recover it, CHECK reads the marker = proof which copy leaked.
  After tagging it offers to ALSO watch the file (fontcache) so it ALERTS on open too.

  WHICH ROUTE FOR WHICH FILE (use them all):
   - Office/web that fetch on open (.docx .svg .html) -> TRIPWIRE [a]  (alerts, needs catcher)
   - ANY file incl .txt, alert on open               -> TRIPWIRE [b]  (watch w/ fontcache, no catcher)
   - Flat files / images, prove a leak (no alert)    -> TRACE
   - Best believable bait (alert + prove leak)       -> TRACE, then say YES to 'also watch'""",
"CHECK": """CHECK — forensics. Point it at any file or picture; it scans for an embedded
  marker (PNG pixels / JPG comment / file trailer) and prints it if found. Use it to
  confirm a recovered/leaked file is one of yours and read its tag.""",
"WIPE": """WIPE — leave no trace. Securely shreds the tool's local footprint:
  ~/.triptrap (your config, the token->label MAP of all your traps, the hit log) AND
  removes the installed 'fontcache' watcher + its boot entry. Optionally deletes THIS
  script too. Workflow: plant your traps -> WIPE -> nothing on the machine shows a
  tripwire system ever existed (only your innocent-looking bait remains). Save your
  token->label notes OFF the machine first if you still need them.""",
}
def show_help(word):
    clear(); print(c(CY, f"\n   === {word} ===\n"))
    for line in HELP[word].splitlines(): print(c(D, "   " + line))


# ── prompts ─────────────────────────────────────────────────
def ask(p): return input(c(G, f"   {p}\n   > ")).strip().strip('"').strip("'")
def ask_ne(p):
    v = ask(p)
    if not v: print(c(R, "   [-] nothing entered — back to menu."))
    return v or None
def ask_file(p):
    while True:
        v = ask(p)
        if v == "": return None
        q = Path(v).expanduser()
        if q.is_file(): return q
        print(c(R, "   [-] can't find that. try again (blank = back)."))
def ask_marker():
    print(c(D, "   MARKER = a secret word YOU choose (e.g. blue-falcon-77). It's hidden inside"))
    print(c(D, "   the file so no one sees it. If the file ever leaks, CHECK reads it back ="))
    print(c(D, "   proof that copy was yours. Pick something only you'd recognize.\n"))
    return ask_ne("Your secret marker word")


# ── ntfy setup (shared) ─────────────────────────────────────
def ensure_topic() -> str | None:
    cfg = load_cfg()
    if cfg.get("ntfy_topic"):
        return cfg["ntfy_topic"]
    print(c(D, "\n   No ntfy token yet — let's set one up (this is your phone alert channel)."))
    print(c(G, "     [1]  Generate a new random token  (recommended)"))
    print(c(G, "     [2]  Type my own"))
    topic = ("trap-" + secrets.token_hex(5)) if ask("pick") != "2" else ask_ne("Your ntfy token")
    if not topic: return None
    cfg["ntfy_topic"] = topic; save_cfg(cfg)
    print(c(CY, "\n   ====== ADD THIS IN THE ntfy APP ======"))
    print(c(Y,  f"     token    : {topic}"))
    print(c(Y,  f"     full URL : {NTFY_SRV}/{topic}"))
    print(c(CY, "   ======================================"))
    print(c(D,  f"   ntfy app -> [+] -> paste the token (server {NTFY_SRV}) -> Subscribe"))
    if ask("\n   Send a TEST alert now? (Y/n):").lower() not in ("n", "no"):
        if push_ntfy(topic, "triptrap test — if you see this, alerts work."):
            print(c(G, "   [+] test sent — check your phone."))
    return topic


# ── TRIPWIRE creation ───────────────────────────────────────
DOC_TYPES = {"1": ("docx", "Word document"), "2": ("svg", "SVG image"), "3": ("html", "HTML page")}
def make_doc_canary():
    tip("DOCUMENT TRAP — makes a Word/SVG/HTML file that secretly calls home the",
        "moment it's OPENED, even on someone else's computer. It needs a 'catcher'",
        "web address (a VPS or free Cloudflare Tunnel). Advanced. For the easy route,",
        "go back and pick [b] Watch — no server needed.")
    cfg = load_cfg()
    if "base_url" not in cfg:
        print(c(Y, "   [!] Alerting documents need a public catcher URL (VPS/tunnel)."))
        b = ask_ne("Catcher base URL (e.g. https://abc.trycloudflare.com)  [blank=skip]")
        if not b: return
        cfg["base_url"] = b.rstrip("/"); save_cfg(cfg)
    topic = ensure_topic()
    if not topic: return
    print()
    for k, (_, desc) in DOC_TYPES.items(): print(c(G, f"     [{k}]  {desc}"))
    sel = ask("pick")
    if sel not in DOC_TYPES: return
    kind, _ = DOC_TYPES[sel]
    name = ask_ne(f"Name (e.g. budget.{kind})")
    if not name: return
    ext = Path(name).suffix.lower()
    if ext in FLAT_EXTS:
        print(c(Y, f"   [!] A token can NOT be embedded in a {ext} file (it can't fetch a URL on open)."))
        if ask("   Do you wish to make this a TRACE file instead? (Y/n):").lower() not in ("n", "no"):
            menu_trace(); return
        print(c(R, "   [-] cancelled — give it a .docx/.svg/.html name, or use TRIPWIRE [b] to watch it.")); return
    dest = ask_ne("PATH to the folder (e.g. ~/Documents)")
    label = dest and ask_ne("Label for YOU (the alert shows this)")
    if not label: return
    out = (Path(dest).expanduser() / name).resolve(); out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists(): print(c(R, "   [-] file already there.")); return
    tid = secrets.token_hex(8); url = f"{cfg['base_url']}/{tid}.gif"
    if kind == "docx": make_docx(url, out, label)
    elif kind == "svg": make_svg(url, out)
    else: make_html(url, out)
    os.chmod(out, 0o600)
    db_add({"id": tid, "label": label, "path": str(out), "kind": kind, "created": time.strftime("%Y-%m-%dT%H:%M:%S")})
    print(c(G, f"\n   [+] alerting {kind} created: {out}"))
    print(c(G, f"   [+] calls: {url}")); print(c(Y, "   [!] listener + catcher must be running."))

WOS = {"1": "linux", "2": "android", "3": "windows"}
def make_watcher_canary():
    tip("WATCH TRAP — watches files you choose and buzzes your phone the instant one",
        "is opened. No web server needed (easiest), and it works for .txt and ANY file.",
        "Steps: 1) set up your phone alert  2) pick the device  3) list the files to watch.")
    topic = ensure_topic()
    if not topic: return
    print(c(G, "\n   Target OS for the watcher (the device the files live on):"))
    print(c(G, "     [1]  Linux    [2]  Android    [3]  Windows"))
    sel = ask("pick")
    if sel not in WOS: return
    tgt = WOS[sel]
    print(c(D, "   Files/folders to watch (one per line; blank line = done). Use real paths"))
    print(c(D, f"   as they exist on the {tgt.upper()} machine (e.g. ~/Notes or C:\\Users\\me\\Notes):"))
    paths = []
    while True:
        v = ask(f"PATH to watch #{len(paths)+1} (blank=done)")
        if not v: break
        paths.append(v)
    if not paths: print(c(R, "   [-] no paths.")); return
    fname, text = build_watcher(tgt, topic, paths)
    if tgt == local_os():
        note = deploy_local_watch(topic, paths)
        print(c(G, f"\n   [+] watcher '{WATCHER_NAME}' deployed on this machine"))
        print(c(D, f"   [*] {note}"))
    else:
        out = Path.home() / fname
        out.write_text(text)
        if tgt != "windows": os.chmod(out, 0o755)
        print(c(G, f"\n   [+] watcher written: {out}"))
        print(c(Y, f"   [!] copy to the {tgt.upper()} machine and run it:"))
        if tgt == "android": print(c(D, "       put in /data/adb/service.d/ (root) — runs at boot"))
        if tgt == "windows": print(c(D, "       powershell -ExecutionPolicy Bypass -File fontcache.ps1 -Install"))
        if tgt == "linux":   print(c(D, f"       chmod +x {fname}; ./{fname} &  (or add to autostart)"))
    print(c(D, f"   [*] pushes ntfy '{topic}' directly on access — no catcher needed."))

def menu_tripwire():
    clear(); block(SEC["TRIPWIRE"]); print()
    tip("Make bait that ALERTS your phone when it's opened. Two ways — pick one:")
    print(c(G, "     [a]  Alerting document  (Word/SVG/HTML — fires on OPEN; needs catcher)"))
    print(c(G, "     [b]  Watch a file/folder (fontcache — fires on open; no server)  <- easiest"))
    print(c(D, "          (not sure? press Enter to go back, then type ABOUT)"))
    sel = ask("pick a or b").lower()
    if sel == "a": make_doc_canary()
    elif sel == "b": make_watcher_canary()


# ── TRACE / CHECK / WIPE ────────────────────────────────────
IMG_EXTS = (".png", ".jpg", ".jpeg", ".bmp")
DECOY = {
 ".txt": "site,user,pass\nmail.proton.me,admin,Sup3r$ecret!\nbank portal,4471-acct,PIN 7741\n",
 ".csv": "service,username,secret\nrootvault,owner,9f2k-Q!x\naws,deploy,AKIAIOSFODNN7EXAMPLE\n",
 ".json": '{\n  "api_key": "sk-live-REDACTED-do-not-share",\n  "db": "postgres://admin:hunter2@10.0.0.5/prod"\n}\n',
 ".log": "2026-06-13 02:14:09 LOGIN ok user=root from=10.0.0.9\n2026-06-13 02:14:11 vault unlocked\n",
}

def tag_in_place(path: Path, token: str) -> str:
    """Add the marker to the file as-is (same name/location). Images re-embed;
    flat files get the trailer appended."""
    if path.suffix.lower() in IMG_EXTS:
        if not _pil(): raise RuntimeError("images need: apt install python3-pil python3-numpy")
        tmp = path.with_name(path.stem + "__tt_tmp" + path.suffix)
        how = img_embed(path, token, tmp); os.replace(tmp, path); return how
    path.write_bytes(path.read_bytes() + _pack(token))
    return "hidden in file trailer"

def _trace_finish(out: Path, how: str, token: str):
    if extract_any(out) != token:
        print(c(R, "   [-] verify failed.")); return
    os.chmod(out, 0o600)
    print(c(G, f"\n   [+] TAGGED ({how}) -> {out}"))
    print(c(Y, "   [!] The tag proves a leaked copy is yours (no alert on its own)."))
    if local_os() in ("linux", "android") and ask(
            "\n   Also WATCH this file so it ALERTS your phone when opened? (Y/n):").lower() not in ("n", "no"):
        topic = ensure_topic()
        if topic:
            print(c(G, "   [+] " + deploy_local_watch(topic, [str(out)])))
            print(c(G, f"   [+] '{out.name}' now BOTH traces and alerts on open."))

def trace_create_new():
    name = ask_ne("File NAME to create (e.g. logins.txt):")
    if not name: return
    if Path(name).suffix.lower() in IMG_EXTS:
        print(c(Y, "   [!] For images, use [2] on a real photo (can't fake a believable image).")); return
    folder = ask_ne("PATH to the folder to create it in (e.g. ~/Desktop):")
    if not folder: return
    out = (Path(folder).expanduser() / name).resolve(); out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and ask(f"   {out} exists — overwrite? (y/N):").lower() not in ("y", "yes"):
        print(c(D, "   cancelled")); return
    print(c(D, "   Paste believable contents; end with a single '.' on its own line"))
    print(c(D, "   (or just '.' right away to use a decoy template):"))
    lines = []
    while True:
        try: ln = input(c(G, "   | "))
        except EOFError: break
        if ln.strip() == ".": break
        lines.append(ln)
    body = "\n".join(lines) if lines else DECOY.get(Path(name).suffix.lower(), "# confidential — internal only\n")
    token = ask_marker()
    if not token: return
    out.write_text(body if body.endswith("\n") else body + "\n")
    try: how = tag_in_place(out, token)
    except Exception as e: print(c(R, f"   [-] {e}")); return
    _trace_finish(out, how, token)

def trace_tag_existing():
    src = ask_file("PATH to the file you already made (tagged IN PLACE):")
    if not src: return
    token = ask_marker()
    if not token: return
    try: how = tag_in_place(src.resolve(), token)
    except Exception as e: print(c(R, f"   [-] {e}")); return
    _trace_finish(src.resolve(), how, token)

def menu_trace():
    clear(); block(SEC["TRACE"]); print()
    tip("TRACE hides a secret MARKER (a word you pick) inside a file so you can PROVE",
        "it's yours if it ever leaks. It won't buzz on its own — but after tagging,",
        "it offers to also WATCH the file so it alerts too. Best for .txt/flat files.")
    print(c(G, "     [1]  CREATE a new decoy file   (I write it + tag it — nothing needed)"))
    print(c(G, "     [2]  TAG a file I already made (tag it in place — keeps name/location)"))
    sel = ask("pick 1 or 2")
    if sel == "1": trace_create_new()
    elif sel == "2": trace_tag_existing()

URL_RE = re.compile(rb"https?://[^\s\"'<>)]{4,}")
KNOWN_CANARY = (b"canarytokens.com", b"canarytokens.org", b"canarytokens.net", b"canary.tools")
def detect_callbacks(path):
    """Forensic: does this file phone home / track whoever opens it? Finds canary
    services, Office external refs, PDF active content, and web bugs (mine or anyone's)."""
    findings = []
    try: data = path.read_bytes()[:5_000_000]
    except Exception: return findings
    ext = path.suffix.lower(); urls = set(URL_RE.findall(data))
    for u in urls:
        if any(k in u for k in KNOWN_CANARY):
            findings.append(("KNOWN canary service", u.decode(errors="replace")))
    if data[:2] == b"PK":
        rel_re = re.compile(rb"<Relationship\b[^>]*>")
        tgt_re = re.compile(rb'Target="([^"]+)"')
        try:
            with zipfile.ZipFile(path) as z:
                for n in z.namelist():
                    if not n.endswith(".rels"): continue
                    for rel in rel_re.findall(z.read(n)):
                        if b'TargetMode="External"' not in rel: continue
                        m = tgt_re.search(rel)
                        if m and m.group(1).lower().startswith((b"http://", b"https://")):
                            findings.append(("Office calls home (external ref)", m.group(1).decode(errors="replace")))
        except Exception: pass
    if ext == ".pdf" or data[:5] == b"%PDF-":
        for m in (b"/URI", b"/Launch", b"/OpenAction", b"/SubmitForm", b"/GoToR"):
            if m in data: findings.append(("PDF active content", m.decode()))
    if ext in (".svg", ".html", ".htm") or b"<svg" in data[:512].lower() or b"<html" in data[:512].lower():
        for u in urls: findings.append(("web remote ref (possible bug)", u.decode(errors="replace")))
    seen = set(); uniq = []
    for f in findings:
        if f not in seen: seen.add(f); uniq.append(f)
    return uniq

def menu_check():
    clear(); block(SEC["CHECK"]); print()
    tip("Two checks in one: (1) is this MY bait? (reads my hidden marker)  and",
        "(2) does this file PHONE HOME / track whoever opens it? (canary / web-bug scan).")
    p = ask_file("PATH to the file or picture to check:")
    if not p: return
    tok = extract_any(p)
    if tok:
        print(c(G, f"\n   [+] FOUND my marker: {tok}"))
        print(c(D, "   That's the secret word hidden inside — proof this file is your copy."))
    else:
        print(c(Y, "\n   [-] No Trip Trap marker (not mine, or it was stripped out)."))
    cb = detect_callbacks(p)
    if cb:
        print(c(R, "\n   [!] CALL-HOME / CANARY indicators — this file may track whoever opens it:"))
        for kind, val in cb[:12]:
            print(c(Y, f"       - {kind}: {val[:80]}"))
        print(c(D, "   (a canarytokens URL or a remote ref means opening it can alert someone.)"))
    else:
        print(c(D, "\n   No call-home/canary indicators (no embedded URLs or active content)."))

def menu_list():
    clear(); print(c(CY, "   [ MY CANARIES + HITS ]\n"))
    for r in db_all():
        alive = "ok" if Path(r["path"]).exists() else "GONE"
        print(c(G, f"   [{alive:4}] {r['kind']:5} id={r['id']}  {r['label']}"))
    if HITS.exists():
        print(c(CY, "\n   recent hits:"))
        for l in HITS.read_text().splitlines()[-5:]: print(c(R, f"     {l}"))

def menu_wipe() -> bool:
    clear(); block(SEC["WIPE"], R); print()
    tip("WIPE erases every trace of this tool from the machine: your settings, the",
        "secret list of which files are traps, the alert log, AND the watcher. Your",
        "planted bait files stay where they are. It can delete this script too.",
        "Use it when you're done so nothing shows a tripwire system was ever here.")
    if ask("Wipe now? (y/N):").lower() not in ("y", "yes"):
        print(c(D, "   cancelled")); return False
    remove_watcher_local()
    if CFG_DIR.exists():
        for f in sorted(CFG_DIR.rglob("*"), reverse=True):
            if f.is_file(): secure_delete(f)
        shutil.rmtree(CFG_DIR, ignore_errors=True)
    print(c(G, "   [+] footprint + watcher shredded."))
    print(c(Y, "   [!] save your token->label notes off-box if you still need them."))
    if ask("Also delete THIS script? (y/N):").lower() in ("y", "yes"):
        try:
            here = Path(__file__).resolve()
            shutil.rmtree(here.parent / "__pycache__", ignore_errors=True)
            secure_delete(here); print(c(G, f"   [+] {here.name} deleted. No trace.")); return True
        except Exception as e: print(c(R, f"   [-] self-delete failed: {e}"))
    return False

def menu_serve():
    if not load_cfg().get("ntfy_topic"): print(c(R, "   [-] set up a tripwire/ntfy first.")); return
    clear(); print(c(CY, "   [ LISTENER ]\n"))
    port = ask("Port [8080]") or "8080"
    try: serve(int(port))
    except KeyboardInterrupt: print(c(D, "\n   [*] stopped."))
    except Exception as e: print(c(R, f"   [-] {e}"))


# ── main menu ───────────────────────────────────────────────
def menu_loop():
    while True:
        clear(); banner()
        print(c(G, "      1) TRIPWIRE Creation"))
        print(c(G, "      2) TRACE Creation"))
        print(c(G, "      3) CHECK files"))
        print(c(G, "      4) WIPE everything / self-destruct"))
        print(c(G, "      5) Quit"))
        print(c(Y, "\n      New here?  type  ABOUT  for a 60-second plain-English overview."))
        print(c(D, "      help: type any CAPS word -> ABOUT / TRIPWIRE / TRACE / CHECK / WIPE\n"))
        ch = input(c(G, "      > ")).strip()
        u = ch.upper()
        if u in HELP: show_help(u)
        elif ch == "1": menu_tripwire()
        elif ch == "2": menu_trace()
        elif ch == "3": menu_check()
        elif ch == "4":
            if menu_wipe(): return
        elif ch.lower() in ("5", "q", "quit", "exit"): print(c(D, "\n      stay frosty.\n")); return
        elif ch.lower() == "listener": menu_serve()
        elif ch.lower() == "list": menu_list()
        else: continue
        input(c(D, "\n      press Enter..."))


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        serve(int(sys.argv[2]) if len(sys.argv) > 2 else 8080); return
    try: menu_loop()
    except (KeyboardInterrupt, EOFError): print(c(D, "\n      stay frosty.\n"))

if __name__ == "__main__":
    main()
