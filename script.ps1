Set-StrictMode -Version Latest

function Show-Menu {
    param(
        [string]$Title = "操作菜单"
    )
    Clear-Host
    Write-Host "=================================================="
    Write-Host "                $Title"
    Write-Host "=================================================="
    Write-Host "[1] 电源模式"
    Write-Host "    [1] 卓越性能"
    Write-Host "    [2] 高性能"
    Write-Host "    [3] 节能"
    Write-Host "    [4] 平衡"
    Write-Host "[2] 公司特殊配置"
    Write-Host "    [1] 自动登录"
    Write-Host "    [2] 代理设置"
    Write-Host "--------------------------------------------------"
    Write-Host "[Q] 退出"
    Write-Host "=================================================="
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
            Write-Host "无效的电源模式选择。"
            return
        }
    }

    Write-Host "正在设置 $schemeName..."

    # 尝试查找现有方案
    $currentSchemes = powercfg /list
    $existingSchemeLine = $currentSchemes | Select-String -Pattern "$schemeName" -ErrorAction SilentlyContinue

    if ($existingSchemeLine) {
        # 如果找到同名方案，提取其 GUID 并激活
        $existingGuid = ([regex]::Match($existingSchemeLine, "[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")).Value
        Write-Host "找到现有电源方案 '$schemeName'，GUID 为：$existingGuid"
        Write-Host "下一步将执行命令：powercfg -setactive $existingGuid"
        $setActiveResult = powercfg -setactive $existingGuid 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "'$schemeName' 已激活。"
        } else {
            Write-Host "激活 '$schemeName' 失败：$setActiveResult"
        }
    } else {
        # 如果未找到，则复制源方案并激活新方案
        Write-Host "未找到电源方案 '$schemeName'，正在创建..."
            $newSchemeOutput = powercfg -duplicatescheme $sourceGuid 2>&1
            if ($LASTEXITCODE -eq 0) {
                # powercfg -duplicatescheme 的输出格式是 "电源方案 GUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX  (方案名称)"
                # 我们需要使用正则表达式提取 GUID。
                $newSchemeGuid = ([regex]::Match($newSchemeOutput, "[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")).Value
                if (-not [string]::IsNullOrEmpty($newSchemeGuid)) {
                    Write-Host "新方案 '$schemeName' 已创建，GUID 为：$newSchemeGuid"
                    Write-Host "下一步将执行命令：powercfg -setactive $newSchemeGuid"
                    $setActiveResult = powercfg -setactive $newSchemeGuid 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "'$schemeName' ($newSchemeGuid) 已激活。"
                    } else {
                        Write-Host "激活新方案 '$schemeName' ($newSchemeGuid) 失败：$setActiveResult"
                    }
                } else {
                    Write-Host "未能从输出中提取 GUID。原始输出：$newSchemeOutput"
                }
            } else {
                Write-Host "创建新方案 '$schemeName' 失败：$newSchemeOutput"
            }
    }
    Read-Host "按任意键返回主菜单..." | Out-Null
}

function Company-Config {
    param(
        [int]$Choice
    )
    switch ($Choice) {
        1 {
            Write-Host "自动登录功能待实现..."
            # 这里可以添加自动登录的逻辑
        }
        2 {
            Write-Host "正在配置代理设置..."
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:7897"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -Value "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;airchina.com.*;10.10.101.*;*.airchina.com.cn"
            Write-Host "代理设置已完成。"
        }
        default {
            Write-Host "无效的公司配置选择。"
        }
    }
                Read-Host "按任意键返回主菜单..." | Out-Null
}

do {
    Show-Menu
    $mainChoice = Read-Host "请选择一个主选项 (1, 2, Q)"

    switch ($mainChoice) {
        "1" {
            $powerChoice = Read-Host "请选择电源模式 (1-4)"
            if ($powerChoice -as [int]) {
                Set-PowerScheme -Choice ([int]$powerChoice)
            } else {
                Write-Host "无效输入，请重新选择。"
    Read-Host "按任意键返回主菜单..." | Out-Null
            }
        }
        "2" {
            $companyChoice = Read-Host "请选择公司特殊配置 (1-2)"
            if ($companyChoice -as [int]) {
                Company-Config -Choice ([int]$companyChoice)
            } else {
                Write-Host "无效输入，请重新选择。"
                Read-Host "按任意键返回主菜单..." | Out-Null
            }
        }
        "q" {
            Write-Host "退出脚本。"
        }
        "Q" {
            Write-Host "退出脚本。"
        }
        default {
            Write-Host "无效选择，请重新输入。"
            Read-Host "按任意键返回主菜单..." | Out-Null
        }
    }
} while ($mainChoice -ne "q" -and $mainChoice -ne "Q")
