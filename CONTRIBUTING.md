# Contributing

Keep checks small, deterministic, and read-only by default. A remediation is accepted only when it has:

1. a reliable current-state check;
2. an explicit backup strategy;
3. atomic writes where possible;
4. syntax/semantic validation;
5. rollback behavior;
6. tests covering the failure path.

Run `pytest` before submitting changes.
