# RemediAX — Start both servers cleanly
# Usage: .\start.ps1

Write-Host "Stopping any existing servers..." -ForegroundColor Yellow

# Kill anything on port 3000 and 8001
$ports = @(3000, 8001)
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($conn in $conns) {
        $pid2 = $conn.OwningProcess
        if ($pid2 -gt 4) {
            Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
        }
    }
}

# Kill any leftover node processes
Stop-Process -Name "node" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "Starting FastAPI backend on port 8001..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'c:\Users\T460S\nileshvary-ai-security-engine'; uvicorn api.main:app --host 0.0.0.0 --port 8001 --reload" -WindowStyle Normal

Start-Sleep -Seconds 3

Write-Host "Starting Next.js frontend on port 3000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'c:\Users\T460S\nileshvary-ai-security-engine\remediax-ui'; npx next dev" -WindowStyle Normal

Start-Sleep -Seconds 5

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  RemediAX is starting up!" -ForegroundColor Green
Write-Host "  Frontend: http://localhost:3000" -ForegroundColor Green
Write-Host "  Backend:  http://localhost:8001" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Two terminal windows have opened." -ForegroundColor Yellow
Write-Host "Wait ~10 seconds then open http://localhost:3000" -ForegroundColor Yellow
