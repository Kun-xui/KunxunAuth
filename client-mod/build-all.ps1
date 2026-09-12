<#
.SYNOPSIS
    依次构建 KunxunAuth Device 的三个加载器模块，并把产物收拢到 dist\。

.DESCRIPTION
    三个模块是三个互相独立的 Gradle 工程，所以这里就是一个接一个地跑，
    而不是用 Gradle 的多模块构建。这样做的代价是启动三次 Gradle，
    好处是任何一个加载器构建失败都不会连累另外两个——对于这种
    「三个加载器版本敏感度完全不同」的工程，能交出可用产物比省几十秒更重要。

    对 JDK 的要求：
      - 构建本身需要 JDK 25（MC 26.2 的字节码就是 25）。
      - Forge 额外需要 JDK 8：ForgeGradle 的 mavenizer 在 modifyAccess 这一步
        必须用 JDK 8 的工具，本机没有的话它会自己去 Adoptium 下载（约 106 MB），
        所以第一次跑 Forge 请留足时间和磁盘。

.NOTES
    走 HTTP 代理的机器上，除了 Gradle 自己的代理配置，还要留意
    ForgeGradle 的子进程用的是 JDK 的 HttpClient，不读 HTTP_PROXY 环境变量，
    必要时用 JAVA_TOOL_OPTIONS 把 -Dhttps.proxyHost / -Dhttps.proxyPort 传下去。
#>

$ErrorActionPreference = 'Continue'

$root    = $PSScriptRoot
$dist    = Join-Path $root 'dist'
$modules = @('fabric', 'neoforge', 'forge')
$version = '1.0.0'

New-Item -ItemType Directory -Force -Path $dist | Out-Null

# toolchain 声明的是 25，但如果 JAVA_HOME 指的不是 25，Gradle 会去别处找 JDK，
# 找不到时报错很难看懂，所以在这里先自己检查一遍，把问题说清楚。
if (-not $env:JAVA_HOME) {
    Write-Error '请先把 JAVA_HOME 指向 JDK 25 再运行本脚本。'
    exit 1
}

$results = @()

foreach ($module in $modules) {
    $dir = Join-Path $root $module
    Write-Host ''
    Write-Host "===== 构建 $module =====" -ForegroundColor Cyan

    Push-Location $dir
    & (Join-Path $dir 'gradlew.bat') build --console=plain
    $code = $LASTEXITCODE
    Pop-Location

    $jarName = "KunxunAuth-Device-$version-$module.jar"
    $jarPath = Join-Path $dist $jarName
    $built   = Join-Path $dir "build\libs\$jarName"

    if ($code -eq 0 -and (Test-Path $built)) {
        Copy-Item $built $dist -Force
        $size = (Get-Item $jarPath).Length
        Write-Host "$module 成功：$jarPath ($size 字节)" -ForegroundColor Green
        $results += [pscustomobject]@{ 模块 = $module; 结果 = '成功'; 大小 = $size }
    }
    else {
        Write-Host "$module 失败（退出码 $code）" -ForegroundColor Red
        $results += [pscustomobject]@{ 模块 = $module; 结果 = "失败(退出码 $code)"; 大小 = 0 }
    }
}

Write-Host ''
Write-Host '===== 汇总 =====' -ForegroundColor Cyan
$results | Format-Table -AutoSize
