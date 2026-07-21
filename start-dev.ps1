$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevOastCallback = "http://host.docker.internal:8000/oast"
$DevOastPoll = "http://localhost:8000/oast/poll"

$BackendCmd = "cd '$RootDir\backend'; `$env:Path = '$RootDir\.venv\Scripts;' + `$env:Path; uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
$ScannerCmd = "cd '$RootDir\scanner'; `$env:Path = '$RootDir\.venv\Scripts;' + `$env:Path; if (-not `$env:OAST_CALLBACK_BASE_URL) { `$env:OAST_CALLBACK_BASE_URL = '$DevOastCallback' }; if (-not `$env:OAST_POLL_URL) { `$env:OAST_POLL_URL = '$DevOastPoll' }; python -m app.worker"
$FrontendCmd = "cd '$RootDir\frontend'; npm run dev"

Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $BackendCmd -WindowStyle Normal
Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $ScannerCmd -WindowStyle Normal
Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $FrontendCmd -WindowStyle Normal
