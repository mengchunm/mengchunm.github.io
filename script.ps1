Set-StrictMode -Version Latest

# 全局变量
$script:scriptDir = "$env:USERPROFILE\LoginScript"
$script:logFile = "$script:scriptDir\login_script.log"
$script:taskName = "NetworkLoginScript"

# ASCII艺术相关函数
function Convert-BBCodeToAnsi {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputString
    )

    $colorTagRegex = '(\[color=(?<hex>#[a-fA-F0-9]{6})\]|<span style="color:(?<hex>#[a-fA-F0-9]{6})">)'

    $matchEvaluator = {
        param($match)
        $hex = $match.Groups['hex'].Value.TrimStart('#')
        $r = [System.Convert]::ToInt32($hex.Substring(0, 2), 16)
        $g = [System.Convert]::ToInt32($hex.Substring(2, 2), 16)
        $b = [System.Convert]::ToInt32($hex.Substring(4, 2), 16)
        return "$([char]27)[38;2;${r};${g};${b}m"
    }

    $processedString = [regex]::Replace($InputString, $colorTagRegex, $matchEvaluator)
    $processedString = $processedString -replace '(\[/color\]|</span>)', "$([char]27)[0m"
    $processedString = $processedString -replace '\[/?(size|font)[^\]]*\]', ''

    return $processedString
}

function Get-AsciiArtDimensions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AsciiContent,

        [Parameter(Mandatory=$false)]
        [switch]$Detailed  # 返回详细信息，包括每行的起始位置
    )

    $plainText = $AsciiContent -replace '\[/?[^\]]+\]', ''
    $plainText = $plainText -replace '<[^>]+>', ''

    $lines = $plainText -split "`n"
    $nonEmptyLines = $lines | Where-Object { $_.Trim() -ne '' }

    $height = $nonEmptyLines.Count
    $width = 0
    $minLeftPadding = [int]::MaxValue
    $lineDetails = @()

    foreach ($line in $nonEmptyLines) {
        $trimmedLine = $line.TrimEnd()

        # 计算左侧空白
        $leftPadding = 0
        if ($trimmedLine.Length -gt 0) {
            $leftPadding = $line.Length - $line.TrimStart().Length
            if ($leftPadding -lt $minLeftPadding -and $trimmedLine.Length -gt 0) {
                $minLeftPadding = $leftPadding
            }
        }

        # 计算实际内容宽度
        $contentWidth = $trimmedLine.Length
        if ($contentWidth -gt $width) {
            $width = $contentWidth
        }

        if ($Detailed) {
            $lineDetails += @{
                Content = $trimmedLine
                LeftPadding = $leftPadding
                Width = $contentWidth
            }
        }
    }

    # 如果所有行都是空的，重置最小左边距
    if ($minLeftPadding -eq [int]::MaxValue) {
        $minLeftPadding = 0
    }

    $result = @{
        Width = $width
        Height = $height
        MinLeftPadding = $minLeftPadding
        EffectiveWidth = $width - $minLeftPadding  # 去除最小左边距后的实际宽度
    }

    if ($Detailed) {
        $result.LineDetails = $lineDetails
    }

    return $result
}

function Load-AsciiArt {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileName
    )

    $asciiPath = Join-Path $PSScriptRoot "ascii\$FileName"

    if (-not (Test-Path $asciiPath)) {
        return $null
    }

    $content = Get-Content $asciiPath -Raw -Encoding UTF8
    $ansiContent = Convert-BBCodeToAnsi -InputString $content
    $dimensions = Get-AsciiArtDimensions -AsciiContent $content -Detailed

    return @{
        Content = $ansiContent
        Lines = $ansiContent -split "`n"
        Width = $dimensions.Width
        Height = $dimensions.Height
        MinLeftPadding = $dimensions.MinLeftPadding
        EffectiveWidth = $dimensions.EffectiveWidth
        LineDetails = $dimensions.LineDetails
    }
}

# 计算字符串的显示宽度（考虑中文字符）
function Get-StringDisplayWidth {
    param(
        [string]$Text
    )

    $width = 0
    foreach ($char in $Text.ToCharArray()) {
        $charCode = [int]$char
        # 中文字符范围和全角字符
        if (($charCode -ge 0x4E00 -and $charCode -le 0x9FFF) -or
            ($charCode -ge 0x3000 -and $charCode -le 0x303F) -or
            ($charCode -ge 0xFF00 -and $charCode -le 0xFFEF)) {
            $width += 2
        } else {
            $width += 1
        }
    }
    return $width
}

function Show-Menu {
    param(
        [string]$Title = "操作菜单",
        [string]$MenuLevel = "main", # "main", "power", "company", "autologin"
        [string]$AsciiArtFile = "isekai.bbcode" # 默认使用isekai ASCII画
    )
    Clear-Host

    # 加载ASCII艺术
    $asciiArt = $null
    if ($AsciiArtFile) {
        $asciiArt = Load-AsciiArt -FileName $AsciiArtFile
    }

    # 准备菜单内容
    $menuLines = @()
    $menuLines += "=================================================="
    $menuLines += "                $Title"
    $menuLines += "=================================================="

    switch ($MenuLevel) {
        "main" {
            $menuLines += "[1] 电源模式"
            $menuLines += "[2] 公司特殊配置"
            $menuLines += "--------------------------------------------------"
            $menuLines += "[Q] 退出"
        }
        "power" {
            $menuLines += "[1] 卓越性能"
            $menuLines += "[2] 高性能"
            $menuLines += "[3] 节能"
            $menuLines += "[4] 平衡"
            $menuLines += "--------------------------------------------------"
            $menuLines += "[B] 返回主菜单"
        }
        "company" {
            $menuLines += "[1] 自动登录配置"
            $menuLines += "[2] 代理设置"
            $menuLines += "--------------------------------------------------"
            $menuLines += "[B] 返回主菜单"
        }
        "autologin" {
            $menuLines += "[1] 安装/更新自动登录脚本"
            $menuLines += "[2] 查看自动登录状态"
            $menuLines += "[3] 卸载自动登录"
            $menuLines += "[4] 查看日志"
            $menuLines += "--------------------------------------------------"
            $menuLines += "[B] 返回公司配置菜单"
        }
    }
    $menuLines += "=================================================="

    # 获取终端宽度
    $terminalWidth = $Host.UI.RawUI.BufferSize.Width

    # 如果有ASCII艺术，先显示ASCII艺术
    if ($asciiArt) {
        foreach ($line in $asciiArt.Lines) {
            $plainLine = $line -replace '(\[color=#[a-fA-F0-9]{6}\]|<span style="color:#[a-fA-F0-9]{6}">|\[/color\]|</span>)', ''
            $lineDisplayWidth = Get-StringDisplayWidth -Text $plainLine
            $leftPadding = [Math]::Max(0, [Math]::Floor(($terminalWidth - $lineDisplayWidth) / 2))
            Write-Host (" " * $leftPadding) -NoNewline
            Write-Host $line
        }
        Write-Host "" # 在ASCII艺术后添加空行
    }

    # 显示菜单 (左对齐)
    foreach ($line in $menuLines) {
        Write-Host $line
    }

    # 确保颜色重置
    Write-Host "$([char]27)[0m" -NoNewline

    # 添加ASCII尺寸信息（调试用）
    if ($asciiArt -and $env:DEBUG_ASCII) {
        Write-Host "`n[ASCII Info: Width=$($asciiArt.Width), Height=$($asciiArt.Height)]" -ForegroundColor DarkGray
    }
}

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # 创建日志目录如果不存在
    if (-not (Test-Path (Split-Path $script:logFile))) {
        New-Item -ItemType Directory -Path (Split-Path $script:logFile) -Force | Out-Null
    }

    # 写入日志文件
    Add-Content -Path $script:logFile -Value $logMessage -ErrorAction SilentlyContinue

    # 根据级别显示不同颜色
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message }
    }
}

function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-PowerScheme {
    param(
        [int]$Choice
    )
    $sourceGuid = ""
    $schemeName = ""

    switch ($Choice) {
        1 {
            $sourceGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61" # 卓越性能
            $schemeName = "卓越性能"
        }
        2 {
            $sourceGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" # 高性能
            $schemeName = "高性能"
        }
        3 {
            $sourceGuid = "a1841308-3541-4fab-bc81-f71556f20b4a" # 节能
            $schemeName = "节能"
        }
        4 {
            $sourceGuid = "381b4222-f694-41f0-9685-ff5bb260df2e" # 平衡
            $schemeName = "平衡"
        }
        default {
            Write-LogMessage "无效的电源模式选择。" -Level "ERROR"
            return
        }
    }

    Write-LogMessage "正在设置 $schemeName..."

    # 尝试查找现有方案
    $currentSchemes = powercfg /list
    $existingSchemeLine = $currentSchemes | Select-String -Pattern "$schemeName" -ErrorAction SilentlyContinue

    if ($existingSchemeLine) {
        # 如果找到同名方案，提取其 GUID 并激活
        $existingGuid = ([regex]::Match($existingSchemeLine, "[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")).Value
        Write-LogMessage "找到现有电源方案 '$schemeName'，GUID 为：$existingGuid"
        $setActiveResult = powercfg -setactive $existingGuid 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "'$schemeName' 已激活。" -Level "SUCCESS"
        } else {
            Write-LogMessage "激活 '$schemeName' 失败：$setActiveResult" -Level "ERROR"
        }
    } else {
        # 如果未找到，则复制源方案并激活新方案
        Write-LogMessage "未找到电源方案 '$schemeName'，正在创建..."
        $newSchemeOutput = powercfg -duplicatescheme $sourceGuid 2>&1
        if ($LASTEXITCODE -eq 0) {
            $newSchemeGuid = ([regex]::Match($newSchemeOutput, "[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")).Value
            if (-not [string]::IsNullOrEmpty($newSchemeGuid)) {
                Write-LogMessage "新方案 '$schemeName' 已创建，GUID 为：$newSchemeGuid"
                $setActiveResult = powercfg -setactive $newSchemeGuid 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-LogMessage "'$schemeName' ($newSchemeGuid) 已激活。" -Level "SUCCESS"
                } else {
                    Write-LogMessage "激活新方案 '$schemeName' ($newSchemeGuid) 失败：$setActiveResult" -Level "ERROR"
                }
            } else {
                Write-LogMessage "未能从输出中提取 GUID。原始输出：$newSchemeOutput" -Level "ERROR"
            }
        } else {
            Write-LogMessage "创建新方案 '$schemeName' 失败：$newSchemeOutput" -Level "ERROR"
        }
    }
    Read-Host "按任意键返回..." | Out-Null
}

function Set-ProxySettings {
    try {
        Write-LogMessage "正在配置代理设置..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:7897"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -Value "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;airchina.com.*;10.10.101.*;*.airchina.com.cn"
        Write-LogMessage "代理设置已完成。" -Level "SUCCESS"
    } catch {
        Write-LogMessage "代理设置失败：$($_.Exception.Message)" -Level "ERROR"
    }
    Read-Host "按任意键返回..." | Out-Null
}

function Install-AutoLogin {
    Write-LogMessage "开始安装自动登录脚本..."

    # 验证用户输入
    $username = ""
    $password = ""

    while ([string]::IsNullOrWhiteSpace($username)) {
        $username = Read-Host "请输入用户名"
        if ([string]::IsNullOrWhiteSpace($username)) {
            Write-LogMessage "用户名不能为空！" -Level "WARNING"
        }
    }

    $securePassword = Read-Host "请输入密码" -AsSecureString
    $passwordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))

    if ([string]::IsNullOrWhiteSpace($passwordPlainText)) {
        Write-LogMessage "密码不能为空！" -Level "ERROR"
        return
    }

    # Python脚本内容
    $pythonScript = @'
import requests, time, json, os
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime

LOGIN_BASE_URL = "http://114.114.114.114:90"
LOGIN_PATH = "/login"
USERNAME = "PLACEHOLDER_USERNAME"
PASSWORD = "PLACEHOLDER_PASSWORD"
LOG_FILE = "login_script_python.log"
STATUS_FILE = "login_status.json"

def write_log(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] [{level}] {message}"
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_message + "\n")
    except:
        pass
    print(log_message)

def update_status(status, last_login=None, error_count=0):
    try:
        status_data = {
            "status": status,
            "last_check": datetime.now().isoformat(),
            "last_login": last_login,
            "error_count": error_count
        }
        with open(STATUS_FILE, 'w') as f:
            json.dump(status_data, f)
    except:
        pass

def mc(a):
    if a == 32: return "+"
    if (a < 48 and a not in (45, 46)) or (57 < a < 65) or (90 < a < 97 and a != 95) or a > 122:
        return "%" + "0123456789ABCDEF"[a >> 4] + "0123456789ABCDEF"[a & 15]
    return chr(a)

def m(a):
    return (((a&1)<<7)|((a&2)<<5)|((a&4)<<3)|((a&8)<<1)|((a&16)>>1)|((a&32)>>3)|((a&64)>>5)|((a&128)>>7))

def md6(s):
    return "".join(mc(m(ord(c)) ^ (0x35 ^ i)) for i,c in enumerate(s))

session = requests.Session()
error_count = 0

import re

def _extract_uri_from_response(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    uri_input = soup.find('input', {'id': 'uri', 'name': 'uri'})
    if uri_input and 'value' in uri_input.attrs:
        return uri_input['value']
    parsed_url = urlparse(response.url)
    uri_from_query = parsed_url.query
    if uri_from_query:
        return uri_from_query
    return None

def get_uri_from_login_page():
    try:
        initial_response = session.get(LOGIN_BASE_URL, allow_redirects=True, timeout=10)
        initial_response.raise_for_status()
        strategies = [
            lambda resp: _extract_uri_from_response(resp),
            lambda resp: _get_uri_from_iframe(resp),
            lambda resp: _get_uri_from_js_redirect(resp)
        ]
        for strategy in strategies:
            uri = strategy(initial_response)
            if uri:
                return uri
        write_log(f"Cannot find URI parameter. Final URL: {initial_response.url}", "WARNING")
        return None
    except requests.exceptions.RequestException as e:
        write_log(f"Failed to get login page: {e}", "ERROR")
        return None

def _get_uri_from_iframe(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    iframe = soup.find('iframe')
    if iframe and 'src' in iframe.attrs:
        iframe_src = iframe['src']
        full_iframe_url = urljoin(response.url, iframe_src)
        iframe_response = session.get(full_iframe_url, allow_redirects=True, timeout=10)
        iframe_response.raise_for_status()
        return _extract_uri_from_response(iframe_response)
    return None

def _get_uri_from_js_redirect(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string:
            match = re.search(r'(?:window\.location\.href|document\.location)\s*=\s*["\']([^"\']+)["\']', script.string)
            if match:
                redirect_url_relative = match.group(1)
                full_redirect_url = urljoin(response.url, redirect_url_relative)
                redirect_response = session.get(full_redirect_url, allow_redirects=True, timeout=10)
                redirect_response.raise_for_status()
                return _extract_uri_from_response(redirect_response)
    return None

def login():
    global error_count
    uri = get_uri_from_login_page()
    if not uri:
        write_log("Cannot get URI, login failed.", "ERROR")
        error_count += 1
        update_status("error", error_count=error_count)
        return False

    data = {
        "uri": uri,
        "terminal": "pc",
        "login_type": "login",
        "check_passwd": "1",
        "username": USERNAME,
        "password": md6(PASSWORD),
        "password1": ""
    }

    try:
        r = session.post(f"{LOGIN_BASE_URL}{LOGIN_PATH}", data=data, timeout=10)
        if "login success" in r.text.lower() or "success" in r.text.lower():
            write_log("Login successful", "SUCCESS")
            error_count = 0
            update_status("logged_in", last_login=datetime.now().isoformat(), error_count=0)
            return True
        write_log("Login failed - invalid credentials or response", "ERROR")
        error_count += 1
        update_status("login_failed", error_count=error_count)
        return False
    except Exception as e:
        write_log(f"Login request failed: {e}", "ERROR")
        error_count += 1
        update_status("error", error_count=error_count)
        return False

def logged_in():
    try:
        r = session.get(f"{LOGIN_BASE_URL}{LOGIN_PATH}", timeout=10)
        is_logged = "login success" in r.text.lower() or "success" in r.text.lower()
        if is_logged:
            update_status("logged_in")
        else:
            update_status("not_logged_in")
        return is_logged
    except:
        update_status("error")
        return False

def main():
    write_log("Starting auto-login script, checking every 30 seconds", "INFO")
    update_status("running")

    check_count = 0
    while True:
        try:
            check_count += 1
            if check_count % 10 == 0:  # 每10次检查记录一次
                write_log(f"Completed {check_count} checks", "INFO")

            if not logged_in():
                write_log("Not logged in, attempting to login...", "WARNING")
                if login():
                    write_log("Login successful, continuing monitoring", "SUCCESS")
                else:
                    write_log("Login failed, will retry in next cycle", "WARNING")

            # 如果错误次数过多，增加等待时间
            if error_count > 10:
                write_log(f"Too many errors ({error_count}), waiting 60 seconds", "WARNING")
                time.sleep(60)
            else:
                time.sleep(30)

        except KeyboardInterrupt:
            write_log("Script stopped by user", "INFO")
            update_status("stopped")
            break
        except Exception as e:
            write_log(f"Unexpected error: {e}", "ERROR")
            time.sleep(30)

if __name__ == "__main__":
    main()
'@

    # 替换占位符
    $pythonScript = $pythonScript.Replace("PLACEHOLDER_USERNAME", $username)
    $pythonScript = $pythonScript.Replace("PLACEHOLDER_PASSWORD", $passwordPlainText)

    # 停止现有进程
    Write-LogMessage "停止现有Python进程..."
    Stop-AutoLoginProcess

    # 等待进程完全终止
    Start-Sleep -Seconds 2

    # 创建脚本目录
    if (-not (Test-Path $script:scriptDir)) {
        New-Item -ItemType Directory -Path $script:scriptDir -Force | Out-Null
        Write-LogMessage "创建脚本目录：$script:scriptDir"
    }

    # 保存Python脚本
    $scriptPath = "$script:scriptDir\login_script.py"
    $pythonScript | Out-File -FilePath $scriptPath -Encoding UTF8
    Write-LogMessage "Python脚本已保存到：$scriptPath"

    # 设置Python环境
    if (-not (Install-PythonEnvironment)) {
        Write-LogMessage "Python环境设置失败！" -Level "ERROR"
        return
    }

    # 创建批处理文件
    $batContent = @"
@echo off
cd /d "$script:scriptDir"
if exist "python\pythonw.exe" (
    python\pythonw.exe login_script.py
) else if exist "python\python.exe" (
    python\python.exe login_script.py
) else (
    pythonw.exe login_script.py
)
"@

    $batPath = "$script:scriptDir\run_login.bat"
    $batContent | Out-File -FilePath $batPath -Encoding ASCII

    # 创建VBS文件
    $vbsContent = @"
CreateObject("Wscript.Shell").Run """$batPath""", 0, False
"@

    $vbsPath = "$script:scriptDir\run_login_silent.vbs"
    $vbsContent | Out-File -FilePath $vbsPath -Encoding ASCII

    # 创建计划任务
    if (Create-ScheduledTask) {
        Write-LogMessage "自动登录脚本安装完成！" -Level "SUCCESS"
        Write-LogMessage "脚本位置：$scriptPath"

        # 清理敏感信息
        $passwordPlainText = $null
        $securePassword = $null

        # 自动启动
        Write-Host ""
        $startNow = Read-Host "是否立即启动自动登录？(Y/N)"
        if ($startNow -eq 'Y' -or $startNow -eq 'y') {
            Start-AutoLoginDirect
        }
    } else {
        Write-LogMessage "计划任务创建失败，但脚本已安装。" -Level "WARNING"
    }

    Read-Host "按任意键返回..." | Out-Null
}

function Install-PythonEnvironment {
    $pythonDir = "$script:scriptDir\python"

    # 检查是否已安装Python
    if (Test-Path "$pythonDir\python.exe") {
        Write-LogMessage "Python环境已存在，正在验证..."

        # 验证pip和依赖包
        $pipPath = "$pythonDir\Scripts\pip.exe"
        if (Test-Path $pipPath) {
            Write-LogMessage "正在检查并安装依赖包..."
            & $pipPath install --upgrade requests beautifulsoup4 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage "Python环境验证完成" -Level "SUCCESS"
                return $true
            }
        }
    }

    Write-LogMessage "正在下载并安装Python环境..."
    $pythonUrl = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip"
    $pythonZip = "$script:scriptDir\python.zip"

    try {
        # 下载Python
        Write-LogMessage "下载Python (约15MB)..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($pythonUrl, $pythonZip)

        # 解压Python
        Write-LogMessage "解压Python..."
        Expand-Archive -Path $pythonZip -DestinationPath $pythonDir -Force
        Remove-Item $pythonZip -ErrorAction SilentlyContinue

        # 修复python._pth文件
        $pthFile = "$pythonDir\python311._pth"
        if (Test-Path $pthFile) {
            $pthContent = Get-Content $pthFile
            $pthContent = $pthContent -replace '^#import site', 'import site'
            $pthContent | Set-Content $pthFile
        }

        # 安装pip
        Write-LogMessage "安装pip..."
        $getpipUrl = "https://bootstrap.pypa.io/get-pip.py"
        $getpipPath = "$script:scriptDir\get-pip.py"
        $webClient.DownloadFile($getpipUrl, $getpipPath)

        & "$pythonDir\python.exe" "$getpipPath" 2>&1 | Out-Null

        # 安装依赖包
        Write-LogMessage "安装依赖包..."
        $pipPath = "$pythonDir\Scripts\pip.exe"
        if (Test-Path $pipPath) {
            & $pipPath install requests beautifulsoup4 2>&1 | Out-Null
        } else {
            & "$pythonDir\python.exe" -m pip install requests beautifulsoup4 2>&1 | Out-Null
        }

        # 清理
        Remove-Item "$getpipPath" -ErrorAction SilentlyContinue

        Write-LogMessage "Python环境设置完成" -Level "SUCCESS"
        return $true

    } catch {
        Write-LogMessage "Python环境设置失败：$($_.Exception.Message)" -Level "ERROR"

        # 尝试使用系统Python
        $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
        if ($pythonCmd) {
            Write-LogMessage "将使用系统Python..." -Level "WARNING"
            return $true
        }

        return $false
    }
}

function Create-ScheduledTask {
    if (-not (Test-AdminRights)) {
        Write-LogMessage "需要管理员权限来创建计划任务" -Level "WARNING"
        Write-LogMessage "尝试使用当前用户权限创建任务..."
    }

    $vbsPath = "$script:scriptDir\run_login_silent.vbs"

    # 删除现有任务
    schtasks /delete /tn "$script:taskName" /f 2>$null | Out-Null

    try {
        if (Test-AdminRights) {
            # 管理员权限下使用SYSTEM账户
            $result = schtasks /create /tn "$script:taskName" `
                /tr "wscript.exe `"$vbsPath`"" `
                /sc onstart /ru "SYSTEM" /rl highest /f

            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage "计划任务创建成功（SYSTEM权限）" -Level "SUCCESS"
                return $true
            }
        }

        # 使用当前用户创建任务
        $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Days 0)

        Register-ScheduledTask -TaskName $script:taskName -Action $action `
            -Trigger $trigger -Settings $settings -Force | Out-Null

        Write-LogMessage "计划任务创建成功（用户权限）" -Level "SUCCESS"
        return $true

    } catch {
        Write-LogMessage "计划任务创建失败：$($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-AutoLoginStatus {
    Write-LogMessage "检查自动登录状态..."

    # 检查脚本文件
    $scriptPath = "$script:scriptDir\login_script.py"
    if (Test-Path $scriptPath) {
        Write-Host "✓ 自动登录脚本已安装" -ForegroundColor Green
    } else {
        Write-Host "✗ 自动登录脚本未安装" -ForegroundColor Red
        Read-Host "按任意键返回..." | Out-Null
        return
    }

    # 检查Python环境
    $pythonDir = "$script:scriptDir\python"
    if (Test-Path "$pythonDir\python.exe") {
        Write-Host "✓ Python环境已配置" -ForegroundColor Green
    } else {
        $systemPython = Get-Command python -ErrorAction SilentlyContinue
        if ($systemPython) {
            Write-Host "✓ 使用系统Python" -ForegroundColor Yellow
        } else {
            Write-Host "✗ Python环境未配置" -ForegroundColor Red
        }
    }

    # 检查进程状态
    $pythonProcess = Get-Process | Where-Object {
        $_.ProcessName -match "python" -and $_.Path -like "*$script:scriptDir*"
    } -ErrorAction SilentlyContinue

    if ($pythonProcess) {
        Write-Host "✓ 自动登录正在运行 (PID: $($pythonProcess.Id))" -ForegroundColor Green
    } else {
        Write-Host "✗ 自动登录未运行" -ForegroundColor Yellow
    }

    # 检查状态文件
    $statusFile = "$script:scriptDir\login_status.json"
    if (Test-Path $statusFile) {
        try {
            $status = Get-Content $statusFile | ConvertFrom-Json
            Write-Host ""
            Write-Host "状态信息：" -ForegroundColor Cyan
            Write-Host "  当前状态：$($status.status)"
            Write-Host "  最后检查：$($status.last_check)"
            if ($status.last_login) {
                Write-Host "  最后登录：$($status.last_login)" -ForegroundColor Green
            }
            if ($status.error_count -gt 0) {
                Write-Host "  错误次数：$($status.error_count)" -ForegroundColor Yellow
            }
        } catch {
            Write-LogMessage "无法读取状态文件" -Level "WARNING"
        }
    }

    # 检查计划任务
    Write-Host ""
    $taskInfo = schtasks /query /tn "$script:taskName" /fo LIST /v 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 计划任务已配置" -ForegroundColor Green
        # 解析任务状态
        $taskInfoString = $taskInfo | Out-String
        if ($taskInfoString -match "状态:\s*(.+?)\r?\n") {
            $status = $Matches[1].Trim()
            Write-Host "  任务状态：$status"
        }
        if ($taskInfoString -match "上次运行时间:\s*(.+?)\r?\n") {
            $lastRun = $Matches[1].Trim()
            if ($lastRun -ne "N/A" -and $lastRun -ne "不适用") {
                Write-Host "  上次运行：$lastRun"
            }
        }
        if ($taskInfoString -match "下次运行时间:\s*(.+?)\r?\n") {
            $nextRun = $Matches[1].Trim()
            if ($nextRun -ne "N/A" -and $nextRun -ne "不适用") {
                Write-Host "  下次运行：$nextRun"
            }
        }
    } else {
        Write-Host "✗ 计划任务未配置" -ForegroundColor Yellow
    }

    Read-Host "`n按任意键返回..." | Out-Null
}

function Start-AutoLoginDirect {
    # 内部函数，安装后直接启动，不需要额外的暂停
    Write-LogMessage "启动自动登录..."

    $vbsPath = "$script:scriptDir\run_login_silent.vbs"
    if (-not (Test-Path $vbsPath)) {
        Write-LogMessage "自动登录脚本未安装！" -Level "ERROR"
        return
    }

    # 检查是否已在运行
    $pythonProcess = Get-Process | Where-Object {
        $_.ProcessName -match "python" -and $_.Path -like "*$script:scriptDir*"
    } -ErrorAction SilentlyContinue

    if ($pythonProcess) {
        Write-LogMessage "自动登录已在运行中 (PID: $($pythonProcess.Id))" -Level "WARNING"
        return
    }

    try {
        Start-Process -FilePath "wscript.exe" -ArgumentList "`"$vbsPath`"" -WindowStyle Hidden
        Write-LogMessage "自动登录已启动" -Level "SUCCESS"

        # 等待几秒检查是否成功启动
        Start-Sleep -Seconds 3
        $newProcess = Get-Process | Where-Object {
            $_.ProcessName -match "python" -and $_.Path -like "*$script:scriptDir*"
        } -ErrorAction SilentlyContinue

        if ($newProcess) {
            Write-LogMessage "确认：自动登录正在运行 (PID: $($newProcess.Id))" -Level "SUCCESS"
        } else {
            Write-LogMessage "警告：无法确认进程是否启动" -Level "WARNING"
        }

    } catch {
        Write-LogMessage "启动失败：$($_.Exception.Message)" -Level "ERROR"
    }
}

function Stop-AutoLoginProcess {
    $processes = Get-Process | Where-Object {
        $_.ProcessName -match "python" -and $_.Path -like "*$script:scriptDir*"
    } -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        try {
            Write-LogMessage "停止进程：$($proc.ProcessName) (PID: $($proc.Id))"
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        } catch {
            Write-LogMessage "无法停止进程 $($proc.Id): $($_.Exception.Message)" -Level "WARNING"
        }
    }
}

function Uninstall-AutoLogin {
    Write-Host "确定要卸载自动登录吗？这将删除所有相关文件和配置。" -ForegroundColor Yellow
    $confirm = Read-Host "输入 YES 确认卸载"

    if ($confirm -ne "YES") {
        Write-LogMessage "取消卸载操作"
        Read-Host "按任意键返回..." | Out-Null
        return
    }

    Write-LogMessage "开始卸载自动登录..."

    # 停止进程
    Stop-AutoLoginProcess

    # 删除计划任务
    Write-LogMessage "删除计划任务..."
    schtasks /delete /tn "$script:taskName" /f 2>$null | Out-Null

    # 等待文件释放
    Start-Sleep -Seconds 2

    # 删除文件
    if (Test-Path $script:scriptDir) {
        Write-LogMessage "删除脚本目录..."
        try {
            Remove-Item $script:scriptDir -Recurse -Force -ErrorAction Stop
            Write-LogMessage "自动登录已完全卸载" -Level "SUCCESS"
        } catch {
            Write-LogMessage "部分文件可能正在使用，无法完全删除" -Level "WARNING"
            Write-LogMessage "请手动删除目录：$script:scriptDir" -Level "WARNING"
        }
    }

    Read-Host "按任意键返回..." | Out-Null
}

function View-AutoLoginLog {
    Write-LogMessage "查看日志文件..."

    $pythonLog = "$script:scriptDir\login_script_python.log"
    $psLog = $script:logFile

    if (Test-Path $pythonLog) {
        Write-Host "`n=== Python脚本日志 (最后20行) ===" -ForegroundColor Cyan
        Get-Content $pythonLog -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "Python日志文件不存在" -ForegroundColor Yellow
    }

    if (Test-Path $psLog) {
        Write-Host "`n=== PowerShell脚本日志 (最后10行) ===" -ForegroundColor Cyan
        Get-Content $psLog -Tail 10 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    }

    Write-Host ""
    Write-Host "日志文件位置：" -ForegroundColor Cyan
    Write-Host "  Python日志：$pythonLog"
    Write-Host "  PowerShell日志：$psLog"

    Read-Host "`n按任意键返回..." | Out-Null
}

function AutoLogin-Menu {
    $choice = Read-Host "请选择自动登录操作 (1-4, B返回)"
    switch ($choice) {
        "1" { Install-AutoLogin }
        "2" { Get-AutoLoginStatus }
        "3" { Uninstall-AutoLogin }
        "4" { View-AutoLoginLog }
        "b" { return $false }
        "B" { return $false }
        default {
            Write-LogMessage "无效选择，请重新输入。" -Level "WARNING"
            Read-Host "按任意键返回..." | Out-Null
        }
    }
    return $true
}

function Company-Config {
    param(
        [int]$Choice
    )
    switch ($Choice) {
        1 {
            # 进入自动登录子菜单
            $continueAutoLogin = $true
            while ($continueAutoLogin) {
                Show-Menu -MenuLevel "autologin" -Title "自动登录配置"
                $continueAutoLogin = AutoLogin-Menu
            }
        }
        2 {
            Set-ProxySettings
        }
        default {
            Write-LogMessage "无效的公司配置选择。" -Level "WARNING"
            Read-Host "按任意键返回..." | Out-Null
        }
    }
}

# 检查管理员权限并提示
function Request-AdminElevation {
    if (-not (Test-AdminRights)) {
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "注意：某些功能需要管理员权限" -ForegroundColor Yellow
        Write-Host "建议以管理员身份重新运行此脚本" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow

        $response = Read-Host "是否以管理员权限重新启动？(Y/N)"
        if ($response -eq 'Y' -or $response -eq 'y') {
            try {
                Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
                exit
            } catch {
                Write-Host "无法提升权限，将以当前权限继续运行" -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        } else {
            Write-Host "将以当前权限继续运行，某些功能可能受限" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
}

# 主程序开始
Request-AdminElevation
Write-LogMessage "PowerShell配置工具启动" -Level "INFO"

$script:exitScript = $false
$currentMenu = "main"

do {
    switch ($currentMenu) {
        "main" {
            Show-Menu -MenuLevel "main" -Title "主菜单"
            $choice = Read-Host "请选择一个主选项 (1, 2, Q)"
            switch ($choice) {
                "1" { $currentMenu = "power" }
                "2" { $currentMenu = "company" }
                "q" { $script:exitScript = $true }
                "Q" { $script:exitScript = $true }
                default {
                    Write-LogMessage "无效选择，请重新输入。" -Level "WARNING"
                    Read-Host "按任意键返回..." | Out-Null
                }
            }
        }
        "power" {
            Show-Menu -MenuLevel "power" -Title "电源模式"
            $choice = Read-Host "请选择电源模式 (1-4, B返回)"
            switch ($choice) {
                "1" { Set-PowerScheme -Choice 1 }
                "2" { Set-PowerScheme -Choice 2 }
                "3" { Set-PowerScheme -Choice 3 }
                "4" { Set-PowerScheme -Choice 4 }
                "b" { $currentMenu = "main" }
                "B" { $currentMenu = "main" }
                default {
                    Write-LogMessage "无效选择，请重新输入。" -Level "WARNING"
                    Read-Host "按任意键返回..." | Out-Null
                }
            }
        }
        "company" {
            Show-Menu -MenuLevel "company" -Title "公司特殊配置"
            $choice = Read-Host "请选择公司特殊配置 (1-2, B返回)"
            switch ($choice) {
                "1" { Company-Config -Choice 1 }
                "2" { Company-Config -Choice 2 }
                "b" { $currentMenu = "main" }
                "B" { $currentMenu = "main" }
                default {
                    Write-LogMessage "无效选择，请重新输入。" -Level "WARNING"
                    Read-Host "按任意键返回..." | Out-Null
                }
            }
        }
    }
} while (-not $script:exitScript)

Write-LogMessage "PowerShell配置工具退出" -Level "INFO"
