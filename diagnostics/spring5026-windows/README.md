# Windows scratch-file diagnostic for PR #5026

This temporary fork branch measures Java 17/21 scratch primitives, not the production saver or a complete Windows recovery implementation. Current upstream PR context is `c708d4ff482184446b79111f5de58fb635156aa3`: it improves existing POSIX checkpoint recovery while first saves and non-POSIX stores retain the old copy path. This branch changes neither that PR branch nor `main`.

Only a push to `diag/spring5026-windows-primitive-20261030` triggers these two standard `windows-2022` jobs. Each has a 12-minute limit and 128MiB Java heap. There is no schedule, secret input, package installation, new account, new service or repository-setting change. Both Java versions come from the runner's preinstalled toolchains. Artifacts expire after one day.

The fixture grants the existing anonymous-logon SID inherited read permission. A separate observer process impersonates that token only while opening files and always reverts. The actual current thread token must have user SID `S-1-5-7`, token type `TokenImpersonation` (2) and level `SecurityImpersonation` (2), both before and after the native data open. Querying that thread uses `OpenAsSelf` solely to authorize `TOKEN_QUERY`; the data open stays on the impersonating thread. A query failure or unexpected identity prevents the data open. After reversion there must be no thread token (1008), with the original process SID restored. Error 1347 concerns `SecurityAnonymous` impersonation level, which differs from the anonymous-logon user SID; it is not accepted as identity proof. NTSystem is measured only in the ordinary Java writer; a process SID is never labelled an anonymous caller. A directory handle grants traversal of this synthetic fixture only; `NtCreateFile` requests and checks the child file's data-read access as anonymous, with `OBJ_FORCE_ACCESS_CHECK`. No ancestor ACL is changed. Positive file-read controls run before and after every observation.

Each NEW-stage/OLD-backup role exercises initial caller ACL, default empty file followed by ACL tightening, and exclusive initialization followed by ACL tightening. The early observer retains any data handle it obtains. Initial/final ACLs and the early open are recorded before candidate bytes are written. The first two variants are diagnostic controls containing public synthetic witness bytes; they may deliberately demonstrate unsafe retained access. The exclusive candidate writes only after the final caller-only ACL and no-early-handle gate passes. Both retained-handle reads and fresh opens are measured after close. A failed candidate or inconclusive observer makes the job fail; green does not mean that FileSystemSaver, all stores or impersonated-caller identity is verified.

First-save/dangling-link comparisons, different-owner target authorization, reader-sharing conflict, exact target ACL/file identity and full rollback/ENOSPC tests follow only after this primitive is established. No claim is made for them in this first run. Unsupported stores or module/identity failures are recorded rather than bypassed.

Official references:

- [Standard public runners and privileges](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Workflow push and manual-trigger rules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [New-object DACL inheritance](https://learn.microsoft.com/en-us/windows/win32/secauthz/dacl-for-a-new-object)
- [Anonymous impersonation and reversion](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateanonymoustoken)
- [Thread-token query semantics](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [Actual token-user, type and level information](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
