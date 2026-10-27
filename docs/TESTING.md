# Verification workflow

Use these checks when changing Aegis or preparing a release. The GitHub Actions workflow runs the supported Python matrix, unit suite, shell syntax checks, a SARIF CLI smoke, and a clean wheel installation.

## Local checks

```bash
python -m pip install -e '.[dev]'
python -m compileall -q aegis tests
bash -n scripts/install.sh scripts/uninstall.sh integration/run-container-matrix.sh
python -m pytest
```

The unit suite covers policy validation and migration, profile and exception behavior, report/baseline schemas, signature lifecycle and tamper handling, transaction rollback and conflict protection, CLI exit codes, SARIF output, and the v1.0 compatibility contract.

## Package check

```bash
python -m pip wheel . --no-deps -w dist
python -m venv /tmp/aegis-venv
/tmp/aegis-venv/bin/python -m pip install --no-deps dist/*.whl
/tmp/aegis-venv/bin/aegis --version
/tmp/aegis-venv/bin/aegis policy example | /tmp/aegis-venv/bin/python -m json.tool
/tmp/aegis-venv/bin/python -m pip check
```

## Disposable integration checks

Run the container matrix for package and platform-adapter behavior:

```bash
./integration/run-container-matrix.sh
# or
CONTAINER_ENGINE=podman ./integration/run-container-matrix.sh
```

Use disposable Linux VMs to exercise service reloads, SSH lockout recovery, firewall persistence, sysctl runtime and reboot behavior, package provenance, install/uninstall upgrades, and rollback after injected failures. Keep an out-of-band console available during remote-access and firewall remediation.

For GitHub Code Scanning ingestion, upload a generated SARIF 2.1.0 report through the repository's configured workflow and confirm the findings appear with the explicitly supplied source locations.
