# fontcache.ps1 — file monitor (Windows). Alerts ntfy on change/create/delete/rename.
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
