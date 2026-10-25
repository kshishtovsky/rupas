@echo off
rem Live ClientHello sniffer (passive, non-destructive): reports SNI/ALPN/ECH
rem of every first outbound TCP 443 ClientHello the inspector can parse.
rem Requires: Administrator console + the WinDivert driver installed.
rem Usage: build\sniffch.cmd [seconds]   (default 20)
setlocal
set "SECS=%~1"
if "%SECS%"=="" set "SECS=20"
set "RUPAS_CH_SNIFF_SECONDS=%SECS%"
cd /d "%~dp0.."
go test -tags live -count=1 -v -run TestLiveCHSniff ./internal/capture/
endlocal
pause
