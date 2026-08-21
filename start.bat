@echo off
setlocal
cd /d "%~dp0"

rem WebView2 GUI automation needs the machine-level policy and therefore an
rem elevated Python process. A batch file cannot carry a UAC manifest itself.
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
  "$root = [IO.Path]::GetFullPath('%~dp0'); $pythonw = (Get-Command pythonw.exe -ErrorAction Stop).Source; Start-Process -FilePath $pythonw -ArgumentList ('"' + (Join-Path $root 'main.py') + '"') -WorkingDirectory $root -Verb RunAs"
endlocal
