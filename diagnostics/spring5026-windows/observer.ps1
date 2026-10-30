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
    positive_thread_sid=$control.ThreadSid; positive_type=$control.ThreadTokenType; positive_level=$control.ImpersonationLevel;
    positive_after_sid=$control.AfterThreadSid; positive_after_type=$control.AfterTokenType; positive_after_level=$control.AfterImpersonationLevel;
    positive_after_query_error=$control.AfterTokenQueryError; positive_reverted_query_error=$control.PostRevertTokenQueryError;
    positive_process_restored=$control.ProcessIdentityRestored; positive_data_open_attempted=$control.DataOpenAttempted
  })
  if (-not $positiveBefore -or -not $callerMatch -or -not $accountMatch) { throw 'Observer identity/positive control failed' }
  $early = [AnonymousReader]::Open($Directory, $Leaf)
  Write-Properties "$SignalPrefix.ready.properties" ([ordered]@{
    positive_before_ok=$positiveBefore; caller_sid_match=$callerMatch; account_sid_match=$accountMatch;
    early_opened=$early.Opened; early_win32_error=$early.Win32Error;
    early_thread_token_error=$early.TokenQueryError; early_context_verified=$early.ContextVerified;
    early_thread_sid=$early.ThreadSid; early_type=$early.ThreadTokenType; early_level=$early.ImpersonationLevel;
    early_after_sid=$early.AfterThreadSid; early_after_type=$early.AfterTokenType; early_after_level=$early.AfterImpersonationLevel;
    early_after_query_error=$early.AfterTokenQueryError; early_reverted_query_error=$early.PostRevertTokenQueryError;
    early_process_restored=$early.ProcessIdentityRestored; early_data_open_attempted=$early.DataOpenAttempted
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
    late_thread_token_error=$late.TokenQueryError; late_context_verified=$late.ContextVerified;
    late_thread_sid=$late.ThreadSid; late_type=$late.ThreadTokenType; late_level=$late.ImpersonationLevel;
    late_after_sid=$late.AfterThreadSid; late_after_type=$late.AfterTokenType; late_after_level=$late.AfterImpersonationLevel;
    late_after_query_error=$late.AfterTokenQueryError; late_reverted_query_error=$late.PostRevertTokenQueryError;
    late_process_restored=$late.ProcessIdentityRestored; late_data_open_attempted=$late.DataOpenAttempted
  })
  if (-not $positiveAfter -or -not $late.ContextVerified) { throw 'Late observer control failed' }
}
finally {
  if ($null -ne $early) { $early.Dispose() }
  if ($null -ne $late) { $late.Dispose() }
}
