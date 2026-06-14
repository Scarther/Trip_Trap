#!/usr/bin/env python3
# fontcache — file-access monitor (stdlib only). Pushes ntfy on watched-path access.
import ctypes, ctypes.util, os, struct, sys, time, urllib.request
TOPIC="__TOPIC__"; SRV="__SRV__"
WATCH=[p for p in r"__WATCH__".split("|") if p]
M=0x1|0x20|0x2|0x40|0x200
def notify(m):
    try: urllib.request.urlopen(urllib.request.Request(SRV+"/"+TOPIC,data=m.encode(),headers={"Title":"fontcache","Priority":"high","Tags":"warning"}),timeout=8)
    except Exception: pass
libc=ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",use_errno=True)
fd=libc.inotify_init(); wd={}
for p in WATCH:
    p=os.path.expanduser(p)
    if os.path.exists(p):
        w=libc.inotify_add_watch(fd,p.encode(),M)
        if w>=0: wd[w]=p
if not wd: sys.exit(0)
SZ=struct.calcsize("iIII")
while True:
    b=os.read(fd,4096); i=0
    while i<len(b):
        w,mask,ck,nl=struct.unpack_from("iIII",b,i); i+=SZ
        nm=b[i:i+nl].split(b"\x00",1)[0].decode("utf-8","replace"); i+=nl
        base=wd.get(w,"?"); full=os.path.join(base,nm) if nm else base
        notify("opened: "+full+" ("+time.strftime("%F %T")+")"); time.sleep(2)
