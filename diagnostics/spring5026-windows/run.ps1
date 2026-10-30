# Copyright 2026 the original author or authors.
# Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
# Distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
param([ValidateSet('17','21')][string]$JavaVersion)
$ErrorActionPreference = 'Stop'
$homePath = [Environment]::GetEnvironmentVariable("JAVA_HOME_${JavaVersion}_X64")
if (-not $homePath) { throw "Preinstalled Java $JavaVersion unavailable; no toolchain download attempted" }
$output = Join-Path $env:GITHUB_WORKSPACE "diag-output/java$JavaVersion"
$classes = Join-Path $output 'classes'
New-Item -ItemType Directory -Force $classes | Out-Null
& (Join-Path $homePath 'bin/javac.exe') --release 17 --add-modules jdk.security.auth,jdk.unsupported -d $classes (Join-Path $PSScriptRoot 'WindowsScratchProbe.java')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $homePath 'bin/java.exe') -Xmx128m -Duser.name=not-the-token-user --add-modules jdk.security.auth,jdk.unsupported -cp $classes WindowsScratchProbe $output $PSScriptRoot
$result = $LASTEXITCODE
if (Test-Path (Join-Path $output 'report.json')) { Get-Content (Join-Path $output 'report.json') }
Remove-Item -Recurse -Force $classes
exit $result
