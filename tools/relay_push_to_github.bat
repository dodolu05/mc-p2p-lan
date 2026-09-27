@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  frp-p2p-lan relay push to GitHub via Aliyun server (claw)
REM  Why: this PC cannot reach github.com directly (SSL fails / proxy 502).
REM  How: git bundle -> scp to claw -> git init+fetch -> push via SSH deploy key.
REM  No token in chat, no token on disk. Double-click to run.
REM  Test mode: set NOPAUSE=1 to skip the pause prompts.
REM  NOTE: keeps working if you rename the repo folder - it auto-detects it.
REM ============================================================

REM Auto-locate the repo folder next to this script (survives folder renames).
set "REPO_DIR="
for /d %%d in ("%~dp0*") do (
    if exist "%%d\.git" if exist "%%d\server\install.sh" set "REPO_DIR=%%d"
)
if not defined REPO_DIR (
    echo [ERR] no git repo folder with server\install.sh found next to this script.
    if not defined NOPAUSE pause
    exit /b 1
)
cd /d "!REPO_DIR!"

REM Proxy env vars would break scp/ssh on this machine; clear them.
set http_proxy=
set https_proxy=
set HTTP_PROXY=
set HTTPS_PROXY=

echo [1/5] Creating bundle from local main...
del /q "%TEMP%\frpp2p.bundle" 2>nul
git bundle create "%TEMP%\frpp2p.bundle" main
if errorlevel 1 (
    echo [ERR] git bundle create failed.
    if not defined NOPAUSE pause
    exit /b 1
)

echo [2/5] Uploading bundle to claw...
scp -q "%TEMP%\frpp2p.bundle" claw:/tmp/frpp2p.bundle
if errorlevel 1 (
    echo [ERR] scp to claw failed ^(check ssh alias "claw"^).
    if not defined NOPAUSE pause
    exit /b 1
)

echo [3/5] Pushing to GitHub from claw over SSH deploy key...
ssh claw "cd /tmp && rm -rf p2ppush && mkdir p2ppush && cd p2ppush && git init -q . && git fetch -q /tmp/frpp2p.bundle refs/heads/main:refs/heads/main && GIT_SSH_COMMAND='ssh -i /root/.ssh/mc_p2p_deploy -o IdentitiesOnly=yes' git push git@github.com:dodolu05/frp-p2p-lan.git refs/heads/main:refs/heads/main 2>&1"
if errorlevel 1 (
    echo [ERR] remote push failed, see the message above.
    if not defined NOPAUSE pause
    exit /b 1
)

echo [4/5] Verifying remote main == local main...
for /f "tokens=*" %%a in ('git rev-parse main') do set LOCAL=%%a
if errorlevel 1 (
    echo [ERR] git rev-parse failed.
    if not defined NOPAUSE pause
    exit /b 1
)
for /f "tokens=1" %%b in ('ssh claw "GIT_SSH_COMMAND='ssh -i /root/.ssh/mc_p2p_deploy -o IdentitiesOnly=yes' git ls-remote git@github.com:dodolu05/frp-p2p-lan.git refs/heads/main"') do set REMOTE=%%b
echo local  main: %LOCAL%
echo remote main: %REMOTE%
if /i not "%LOCAL%"=="%REMOTE%" (
    echo [ERR] sha mismatch - push did NOT land.
    if not defined NOPAUSE pause
    exit /b 1
)

echo [5/5] Cleaning up...
ssh claw "rm -rf /tmp/p2ppush /tmp/frpp2p.bundle" 2>nul
del /q "%TEMP%\frpp2p.bundle" 2>nul
echo ============================================================
echo  PUSH OK - remote main = %REMOTE:~0,7%
echo ============================================================
if not defined NOPAUSE pause
exit /b 0
