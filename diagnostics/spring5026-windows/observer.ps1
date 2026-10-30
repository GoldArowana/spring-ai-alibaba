# Copyright 2026 the original author or authors.
# Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
# Distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
param([string]$Directory, [string]$Leaf, [string]$SignalPrefix, [string]$Output,
      [string]$CallerAccount, [string]$ExpectedSid)
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'AnonymousReader.cs')
$payload = 'SYNTHETIC-CHECKPOINT-5026'
$utf8 = [Text.UTF8Encoding]::new($false)
function Write-Properties($path, $values) {
  $lines = foreach ($key in $values.Keys) { "$key=$($values[$key].ToString().ToLowerInvariant())" }
  [IO.File]::WriteAllLines($path, [string[]]$lines, $utf8)
}
$early = $null
$late = $null
try {
  $callerMatch = [AnonymousReader]::ProcessSid() -eq $ExpectedSid
  $accountMatch = [AnonymousReader]::AccountSid($CallerAccount) -eq $ExpectedSid
  $control = [AnonymousReader]::Open($Directory, 'positive.txt')
  try { $positiveBefore = $control.ContextVerified -and $control.Opened -and $control.ReadText() -eq $payload }
  finally { $control.Dispose() }
  Write-Properties (Join-Path $Output 'preflight.properties') ([ordered]@{
    caller_sid_match=$callerMatch; account_sid_match=$accountMatch;
    positive_opened=$control.Opened; positive_win32_error=$control.Win32Error;
    positive_thread_token_error=$control.TokenQueryError;
    positive_context_verified=$control.ContextVerified; positive_before_ok=$positiveBefore
  })
  if (-not $positiveBefore -or -not $callerMatch -or -not $accountMatch) { throw 'Observer identity/positive control failed' }
  $early = [AnonymousReader]::Open($Directory, $Leaf)
  Write-Properties "$SignalPrefix.ready.properties" ([ordered]@{
    positive_before_ok=$positiveBefore; caller_sid_match=$callerMatch; account_sid_match=$accountMatch;
    early_opened=$early.Opened; early_win32_error=$early.Win32Error;
    early_thread_token_error=$early.TokenQueryError; early_context_verified=$early.ContextVerified
  })
  [IO.File]::WriteAllText("$SignalPrefix.ready", 'ready', $utf8)
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  while (-not [IO.File]::Exists("$SignalPrefix.go")) {
    if ([DateTime]::UtcNow -gt $deadline) { throw 'Writer barrier timed out' }
    Start-Sleep -Milliseconds 25
  }
  $control = [AnonymousReader]::Open($Directory, 'positive.txt')
  try { $positiveAfter = $control.ContextVerified -and $control.Opened -and $control.ReadText() -eq $payload }
  finally { $control.Dispose() }
  $retainedMatches = $early.Opened -and $early.ReadText() -eq $payload
  $late = [AnonymousReader]::Open($Directory, $Leaf)
  $freshMatches = $late.Opened -and $late.ReadText() -eq $payload
  Write-Properties (Join-Path $Output 'result.properties') ([ordered]@{
    positive_after_ok=$positiveAfter; retained_matches_payload=$retainedMatches;
    fresh_opened=$late.Opened; fresh_win32_error=$late.Win32Error; fresh_matches_payload=$freshMatches;
    late_thread_token_error=$late.TokenQueryError; late_context_verified=$late.ContextVerified
  })
  if (-not $positiveAfter -or -not $late.ContextVerified) { throw 'Late observer control failed' }
}
finally {
  if ($null -ne $early) { $early.Dispose() }
  if ($null -ne $late) { $late.Dispose() }
}
