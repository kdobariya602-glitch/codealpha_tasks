# Task 3 — Secure Coding Review Report (Training Sample)

## Scope
This report reviews the included file `audit_sample/intentionally_vulnerable_training_sample.py`. The file is intentionally vulnerable and exists only for training. Do not deploy or run it with untrusted inputs.

## Review method
Manual source inspection plus the CodeLens educational pattern checker. Findings below are based on the source text and should be verified in a controlled test environment.

## Findings

### CR-01 — SQL injection risk
- **Location:** `find_user`, query construction line
- **Evidence:** SQL query is built with an f-string that inserts `username` directly.
- **Impact:** Crafted input could alter the SQL query and expose or modify data.
- **Remediation:** Use a parameterized query, for example `conn.execute("SELECT * FROM users WHERE username = ?", (username,))`.
- **Verification:** Review the final query to confirm user input is passed separately as a parameter; add tests with quotes and SQL metacharacters.

### CR-02 — Command injection risk
- **Location:** `run_lookup`
- **Evidence:** User-controlled text is concatenated into a command passed to `subprocess.run(..., shell=True)`.
- **Impact:** Shell metacharacters may cause unintended command execution.
- **Remediation:** Avoid the shell; pass an argument list, validate expected input, and use a timeout. If the operation does not require a process, use a safe Python API.
- **Verification:** Confirm no user input is interpreted by a shell and add negative tests.

### CR-03 — Unsafe dynamic evaluation
- **Location:** `calculate`
- **Evidence:** `eval(expression)` evaluates text as Python code.
- **Impact:** Untrusted input could execute unintended Python expressions.
- **Remediation:** Do not use `eval` on untrusted input. Use a strict parser or accept only the expected data format.
- **Verification:** Search for remaining unsafe evaluation and test invalid input rejection.

### CR-04 — Hard-coded token-like value
- **Location:** module constant `API_TOKEN`
- **Evidence:** A token-like string is stored directly in source.
- **Impact:** Real secrets can leak through source control or shared files. This sample value is a demo and is not a real credential.
- **Remediation:** Load real secrets from environment variables or a secret manager; rotate any real secret that was exposed.
- **Verification:** Search source and repository history for real secrets and confirm secret scanning is enabled.

## Overall conclusion
The training sample contains four clear insecure patterns. The remediation examples should be implemented and retested before any real application is considered safe. This is a review of the included sample only, not a claim that a separate production application was audited.

## Test record — complete after running tools
- Date:
- Python/tool version:
- Findings confirmed:
- Remediation changes applied:
- Retest results:
- Evidence/screenshots:
