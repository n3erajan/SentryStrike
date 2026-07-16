$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$BackendCmd = "cd '$RootDir\backend'; `$env:Path = '$RootDir\.venv\Scripts;' + `$env:Path; uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
$ScannerCmd = "cd '$RootDir\scanner'; `$env:Path = '$RootDir\.venv\Scripts;' + `$env:Path; python -m app.worker"
$FrontendCmd = "cd '$RootDir\frontend'; npm run dev"

Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $BackendCmd -WindowStyle Normal
Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $ScannerCmd -WindowStyle Normal
Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $FrontendCmd -WindowStyle Normal
