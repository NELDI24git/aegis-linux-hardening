from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from aegis import __version__
from aegis.artifacts import publish_artifact
from aegis.baseline import compare_baseline_data, create_baseline, render_drift
from aegis.checks import ALL_CHECKS
from aegis.context import SystemContext
from aegis.doctor import render_doctor, run_doctor
from aegis.engine.audit import run_audit
from aegis.engine.remediation import RemediationError, apply_fixes, plan_fix, preflight_fixes, supported_fix_ids
from aegis.engine.transaction import list_transactions, rollback_transaction
from aegis.fileio import atomic_write_text
from aegis.eventlog import emit_event
from aegis.exitcodes import AUDIT_THRESHOLD, DRIFT_DETECTED, INTEGRITY_FAILED, OK, PREFLIGHT_FAILED, REMEDIATION_FAILED, RUNTIME_ROLLBACK_FAILED, SNAPSHOT_CHANGES, USAGE_OR_INPUT
from aegis.integrity import IntegrityError, generate_key, sign_file, signature_path, verify_bytes, verify_file
from aegis.inventory.privileged import collect_privileged_files
from aegis.inventory.sockets import collect_listening_sockets
from aegis.models import Severity, Status
from aegis.platform import detect_platform
from aegis.policy import DEFAULT_POLICY_PATH, Policy, PolicyError, example_policy, load_policy_path, migrate_policy_dict
from aegis.profiles import PROFILES, profile_names
from aegis.reporting.console import render_console
from aegis.reporting.html_report import render_html
from aegis.reporting.json_report import render_json
from aegis.reporting.sarif_report import load_location_map, render_sarif
from aegis.snapshots import compare_snapshots, create_snapshot, load_snapshot_data, render_snapshot, render_snapshot_diff


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Linux security audit and safe-hardening framework")
    parser.add_argument("--version", action="version", version=f"Aegis {__version__}")
    parser.add_argument("--root", default=None, help="Operate on a fake filesystem root (testing/development only)")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Run security checks")
    audit.add_argument("--module", choices=sorted({c.module for c in ALL_CHECKS}))
    audit.add_argument("--profile", choices=profile_names(), help="Use a built-in role profile; explicit policy overrides remain authoritative")
    audit.add_argument("--tag", action="append", default=[], help="Run checks matching a tag/module (repeatable)")
    audit.add_argument("--json", dest="json_path", help="Write JSON report to a file")
    audit.add_argument("--html", dest="html_path", help="Write standalone HTML report to a file")
    audit.add_argument("--sarif", dest="sarif_path", help="Write SARIF 2.1.0 output for security-result consumers")
    audit.add_argument("--sarif-location-map", help="JSON mapping Aegis check IDs to repository-relative file locations for GitHub code scanning")
    audit.add_argument("--sign-key", help="HMAC-sign generated JSON/HTML/SARIF report files with this key")
    audit.add_argument("-v", "--verbose", action="store_true", help="Show evidence and remediation details")
    audit.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="Exit non-zero when a failed check meets this severity")

    sub.add_parser("list-checks", help="List available checks and tags")
    sub.add_parser("list-fixes", help="List checks with automatic/conditional remediation")
    profiles = sub.add_parser("profiles", help="List built-in role profiles")
    profiles.add_argument("name", nargs="?", choices=profile_names())
    sub.add_parser("doctor", help="Inspect Aegis runtime prerequisites and optional integrations")

    inventory = sub.add_parser("inventory", help="Inspect security-relevant host inventory")
    inventory.add_argument("kind", choices=("sockets", "suid"))

    baseline = sub.add_parser("baseline", help="Create or compare a trusted host baseline")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    baseline_create = baseline_sub.add_parser("create", help="Capture sockets and SUID/SGID inventory")
    baseline_create.add_argument("output")
    baseline_create.add_argument("--sign-key", help="HMAC-sign the resulting baseline")
    baseline_create.add_argument("--force", action="store_true", help="Replace an existing baseline and signature")
    baseline_compare = baseline_sub.add_parser("compare", help="Compare current state with a baseline")
    baseline_compare.add_argument("baseline_file")
    baseline_compare.add_argument("--verify-key", help="Verify the HMAC signature before comparison")
    baseline_compare.add_argument("--require-signature", action="store_true", help="Reject unsigned baselines")

    snapshots = sub.add_parser("snapshot", help="Capture and compare complete audit snapshots")
    snapshot_sub = snapshots.add_subparsers(dest="snapshot_command", required=True)
    snapshot_create = snapshot_sub.add_parser("create", help="Capture an audit snapshot without changing the host")
    snapshot_create.add_argument("output")
    snapshot_create.add_argument("--module", choices=sorted({c.module for c in ALL_CHECKS}))
    snapshot_create.add_argument("--profile", choices=profile_names())
    snapshot_create.add_argument("--tag", action="append", default=[])
    snapshot_create.add_argument("--host-id", help="Optional stable label used to prevent comparing different hosts")
    snapshot_create.add_argument("--sign-key", help="HMAC-sign the snapshot")
    snapshot_create.add_argument("--force", action="store_true", help="Replace an existing snapshot and signature")
    snapshot_diff = snapshot_sub.add_parser("diff", help="Compare two audit snapshots")
    snapshot_diff.add_argument("before")
    snapshot_diff.add_argument("after")
    snapshot_diff.add_argument("--verify-key", help="Verify signed snapshots before comparison")
    snapshot_diff.add_argument("--require-signature", action="store_true", help="Reject unsigned snapshots")
    snapshot_diff.add_argument("--json", action="store_true", help="Write machine-readable diff JSON to stdout")

    policy = sub.add_parser("policy", help="Validate, migrate, or print a host policy")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_validate = policy_sub.add_parser("validate", help="Validate policy schema and values")
    policy_validate.add_argument("path", nargs="?", default=DEFAULT_POLICY_PATH)
    policy_migrate = policy_sub.add_parser("migrate", help="Migrate a legacy policy to the current schema")
    policy_migrate.add_argument("input")
    policy_migrate.add_argument("output")
    policy_migrate.add_argument("--force", action="store_true", help="Overwrite output if it already exists")
    policy_sub.add_parser("example", help="Print an example policy for the current schema")

    integrity = sub.add_parser("integrity", help="Create/verify HMAC integrity metadata")
    integrity_sub = integrity.add_subparsers(dest="integrity_command", required=True)
    keygen = integrity_sub.add_parser("keygen", help="Create a random 256-bit HMAC key")
    keygen.add_argument("path")
    keygen.add_argument("--force", action="store_true")
    sign = integrity_sub.add_parser("sign", help="Sign a file")
    sign.add_argument("path")
    sign.add_argument("--key", required=True)
    verify = integrity_sub.add_parser("verify", help="Verify a signed file")
    verify.add_argument("path")
    verify.add_argument("--key", required=True)

    plan = sub.add_parser("plan", help="Show planned remediation without changing the system")
    plan.add_argument("check_ids", nargs="+")
    preflight = sub.add_parser("preflight", help="Run remediation safety checks without changing the system")
    preflight.add_argument("check_ids", nargs="+")
    preflight.add_argument("--acknowledge-lockout-risk", action="store_true")
    fix = sub.add_parser("fix", help="Apply supported remediations in one transaction")
    fix.add_argument("check_ids", nargs="+")
    fix.add_argument("--dry-run", action="store_true")
    fix.add_argument("--acknowledge-lockout-risk", action="store_true")

    rollback = sub.add_parser("rollback", help="Restore files and known runtime state from a previous Aegis transaction")
    rollback.add_argument("transaction_id")
    rollback.add_argument("--force", action="store_true")
    rollback.add_argument("--files-only", action="store_true")
    sub.add_parser("transactions", help="List recorded Aegis remediation transactions")
    return parser


def _print_preflight(result) -> None:
    print("Preflight: " + ("PASS" if result.ok else "FAIL"))
    for message in result.messages:
        print(f"  {'OK' if result.ok else '- '} {message}")
    for warning in result.warnings:
        print(f"  WARN {warning}")


def _sign_output(path: str, key: str) -> None:
    sig = sign_file(path, key)
    print(f"Integrity signature written to {sig}")


def _create_baseline_artifact(ctx: SystemContext, output: str, *, sign_key: str | None, force: bool) -> None:
    publish_artifact(
        output,
        lambda staged: create_baseline(ctx, staged),
        sign_key=sign_key,
        force=force,
    )


def _read_snapshot_artifact(path: str, *, verify_key: str | None, require_signature: bool) -> dict:
    target = Path(path)
    if target.is_symlink():
        raise IntegrityError(f"refusing to read a symlink snapshot: {target}")
    data = target.read_bytes()
    signature = signature_path(target)
    has_signature = signature.exists() or signature.is_symlink()
    if require_signature and not verify_key:
        raise IntegrityError("--require-signature requires --verify-key")
    if require_signature and not has_signature:
        raise IntegrityError(f"snapshot signature is required but missing: {signature}")
    if has_signature and not verify_key:
        raise IntegrityError(f"snapshot has a signature; pass --verify-key to verify it: {signature}")
    if verify_key:
        result = verify_bytes(data, target.name, verify_key, signature=signature)
        if not result.ok:
            raise IntegrityError(result.message)
    return load_snapshot_data(data)

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ctx = SystemContext(args.root)

    if args.command == "audit":
        if args.sarif_location_map and not args.sarif_path:
            print("ERROR: --sarif-location-map requires --sarif", file=sys.stderr)
            return USAGE_OR_INPUT
        outputs = [path for path in (args.json_path, args.html_path, args.sarif_path) if path]
        normalized = [os.path.normcase(os.path.abspath(path)) for path in outputs]
        reserved = set(normalized)
        signature_paths = {os.path.normcase(os.path.abspath(path + ".sig")) for path in outputs} if args.sign_key else set()
        generated_paths = reserved | signature_paths
        if len(generated_paths) != len(reserved) + len(signature_paths):
            print("ERROR: report and signature output paths must be different", file=sys.stderr)
            return USAGE_OR_INPUT
        if len(reserved) != len(normalized):
            print("ERROR: JSON, HTML, and SARIF output paths must be different", file=sys.stderr)
            return USAGE_OR_INPUT
        if args.sign_key and not outputs:
            print("ERROR: --sign-key requires at least one report output", file=sys.stderr)
            return USAGE_OR_INPUT
        if args.sign_key:
            key_path = os.path.normcase(os.path.abspath(args.sign_key))
            if key_path in generated_paths:
                print("ERROR: integrity key path conflicts with a report output", file=sys.stderr)
                return USAGE_OR_INPUT
        try:
            findings = run_audit(ctx, args.module, profile=args.profile, tags=set(args.tag))
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return USAGE_OR_INPUT
        platform = detect_platform(ctx)
        policy = Policy.load(ctx)
        profile = args.profile or (policy.profile if policy.explicit and policy.valid else "general")
        print(render_console(findings, platform.display, verbose=args.verbose, profile=profile))
        try:
            locations = load_location_map(args.sarif_location_map) if args.sarif_location_map else None
            report_texts = []
            if args.json_path:
                report_texts.append((args.json_path, render_json(findings, platform=platform.display, profile=profile)))
            if args.html_path:
                report_texts.append((args.html_path, render_html(findings, platform=platform.display, profile=profile)))
            if args.sarif_path:
                report_texts.append((args.sarif_path, render_sarif(findings, platform=platform.display, profile=profile, locations=locations)))
            for output_path, report_text in report_texts:
                atomic_write_text(output_path, report_text)
                print(f"Report written to {output_path}")
                if args.sign_key:
                    _sign_output(output_path, args.sign_key)
        except ValueError as exc:
            print(f"ERROR: invalid report configuration: {exc}", file=sys.stderr)
            return USAGE_OR_INPUT
        except (OSError, IntegrityError) as exc:
            print(f"ERROR: report output/integrity failed: {exc}", file=sys.stderr)
            return INTEGRITY_FAILED
        emit_event(ctx, "audit", details={"profile": profile, "checks": len(findings), "json": bool(args.json_path), "html": bool(args.html_path), "sarif": bool(args.sarif_path)})
        if args.fail_on:
            order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            threshold = order[Severity(args.fail_on.upper())]
            blocking = [f for f in findings if f.status in {Status.FAIL, Status.ERROR} and order.get(f.severity, 0) >= threshold]
            if blocking:
                return AUDIT_THRESHOLD
        return OK

    if args.command == "list-checks":
        for check in ALL_CHECKS:
            print(f"{check.check_id:<9} {check.module:<12} tags={','.join(check.effective_tags()):<18} {check.title}")
        return OK

    if args.command == "list-fixes":
        for check_id in supported_fix_ids():
            print(plan_fix([check_id])[0])
        return OK

    if args.command == "profiles":
        names = [args.name] if args.name else profile_names()
        for name in names:
            p = PROFILES[name]
            ports = ",".join(map(str, sorted(p.default_public_ports))) or "none"
            print(f"{p.name}: {p.description}\n  default_public_ports={ports}\n  tags={','.join(sorted(p.tags)) or 'none'}")
        return OK

    if args.command == "doctor":
        print(render_doctor(run_doctor(ctx)))
        return OK

    if args.command == "inventory":
        if args.kind == "sockets":
            sockets, source = collect_listening_sockets(ctx)
            print(f"Listening sockets ({source})")
            for item in sockets:
                print(item.display())
            print(f"Total: {len(sockets)}")
            return OK
        files, source = collect_privileged_files(ctx)
        print(f"SUID/SGID executables ({source})")
        for item in files:
            print(item.display())
        print(f"Total: {len(files)}")
        return OK

    if args.command == "snapshot":
        if args.snapshot_command == "create":
            try:
                payload = create_snapshot(
                    ctx,
                    module=args.module,
                    profile=args.profile,
                    tags=set(args.tag),
                    host_id=args.host_id,
                )
                publish_artifact(
                    args.output,
                    lambda staged: atomic_write_text(staged, render_snapshot(payload)),
                    sign_key=args.sign_key,
                    force=args.force,
                )
            except FileExistsError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return USAGE_OR_INPUT
            except IntegrityError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return INTEGRITY_FAILED
            except (OSError, ValueError, TypeError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return USAGE_OR_INPUT
            emit_event(ctx, "snapshot.create", details={"snapshot_id": payload["snapshot_id"], "checks": len(payload["findings"]), "signed": bool(args.sign_key)})
            print(f"Snapshot written to {args.output} ({len(payload['findings'])} checks)")
            if args.sign_key:
                print(f"Integrity signature written to {signature_path(args.output)}")
            return OK

        try:
            before = _read_snapshot_artifact(args.before, verify_key=args.verify_key, require_signature=args.require_signature)
            after = _read_snapshot_artifact(args.after, verify_key=args.verify_key, require_signature=args.require_signature)
            diff = compare_snapshots(before, after)
        except IntegrityError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return INTEGRITY_FAILED
        except (OSError, ValueError, TypeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return USAGE_OR_INPUT
        emit_event(ctx, "snapshot.diff", outcome="changes" if diff.has_changes else "clean", details={"before": before["snapshot_id"], "after": after["snapshot_id"], "changes": diff.has_changes, "signature_verified": bool(args.verify_key)})
        if args.json:
            print(json.dumps(diff.to_dict(), indent=2, sort_keys=True))
        else:
            print(render_snapshot_diff(diff))
        return SNAPSHOT_CHANGES if diff.has_changes else OK

    if args.command == "baseline":
        if args.baseline_command == "create":
            try:
                _create_baseline_artifact(ctx, args.output, sign_key=args.sign_key, force=args.force)
                print(f"Baseline written to {args.output}")
                if args.sign_key:
                    print(f"Integrity signature written to {signature_path(args.output)}")
            except FileExistsError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return USAGE_OR_INPUT
            except IntegrityError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return INTEGRITY_FAILED
            except ValueError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return USAGE_OR_INPUT
            except OSError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return INTEGRITY_FAILED
            emit_event(ctx, "baseline.create", details={"output": str(args.output), "signed": bool(args.sign_key)})
            print("Treat a baseline as trusted only after manually reviewing the captured state.")
            return OK

        try:
            baseline_path = Path(args.baseline_file)
            baseline_data = baseline_path.read_bytes()
            baseline_signature = signature_path(baseline_path)
            has_signature = baseline_signature.exists() or baseline_signature.is_symlink()
            if args.require_signature and not args.verify_key:
                print("ERROR: --require-signature requires --verify-key", file=sys.stderr)
                return INTEGRITY_FAILED
            if args.require_signature and not has_signature:
                print("ERROR: baseline signature is required but no signature file exists", file=sys.stderr)
                return INTEGRITY_FAILED
            if has_signature and not args.verify_key:
                print("ERROR: baseline has a signature; pass --verify-key to verify it", file=sys.stderr)
                return INTEGRITY_FAILED
            if args.verify_key:
                result = verify_bytes(baseline_data, baseline_path.name, args.verify_key, signature=baseline_signature)
                if not result.ok:
                    print(f"ERROR: {result.message}", file=sys.stderr)
                    return INTEGRITY_FAILED
                print(result.message)
            drift = compare_baseline_data(ctx, baseline_data)
        except (OSError, ValueError, TypeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return USAGE_OR_INPUT
        print(render_drift(drift))
        emit_event(ctx, "baseline.compare", outcome="drift" if drift.has_drift else "ok", details={"baseline": str(args.baseline_file), "signature_verified": bool(args.verify_key)})
        return DRIFT_DETECTED if drift.has_drift else OK

    if args.command == "policy":
        if args.policy_command == "example":
            print(json.dumps(example_policy(), indent=2))
            return OK
        if args.policy_command == "validate":
            policy = load_policy_path(args.path, allow_legacy=False)
            if not policy.valid:
                print("Policy INVALID", file=sys.stderr)
                for error in policy.validation_errors:
                    print(f"  - {error}", file=sys.stderr)
                return USAGE_OR_INPUT
            print(f"Policy valid (schema v{policy.schema_version}, profile={policy.profile}, exceptions={len(policy.exceptions)})")
            return OK
        target = Path(args.output)
        if target.exists() and not args.force:
            print(f"ERROR: {target} already exists; use --force to overwrite", file=sys.stderr)
            return USAGE_OR_INPUT
        try:
            raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
            migrated = migrate_policy_dict(raw)
        except (OSError, json.JSONDecodeError, PolicyError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return USAGE_OR_INPUT
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(migrated, indent=2) + "\n", encoding="utf-8")
        print(f"Migrated policy written to {target}")
        return OK

    if args.command == "integrity":
        try:
            if args.integrity_command == "keygen":
                target = generate_key(args.path, force=args.force)
                print(f"Integrity key written to {target} with mode 0600")
                return OK
            if args.integrity_command == "sign":
                sig = sign_file(args.path, args.key)
                print(f"Signature written to {sig}")
                return OK
            result = verify_file(args.path, args.key)
            print(result.message)
            return OK if result.ok else INTEGRITY_FAILED
        except (OSError, IntegrityError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return INTEGRITY_FAILED

    if args.command == "plan":
        for action in plan_fix(args.check_ids):
            print(action)
        return OK

    if args.command == "preflight":
        result = preflight_fixes(ctx, args.check_ids, acknowledge_lockout_sensitive=args.acknowledge_lockout_risk, require_lockout_ack=False)
        _print_preflight(result)
        emit_event(ctx, "remediation.preflight", outcome="ok" if result.ok else "failed", details={"checks": args.check_ids})
        return OK if result.ok else PREFLIGHT_FAILED

    if args.command == "fix":
        for action in plan_fix(args.check_ids):
            print(action)
        try:
            txid = apply_fixes(ctx, args.check_ids, dry_run=args.dry_run, acknowledge_lockout_sensitive=args.acknowledge_lockout_risk)
        except RemediationError as exc:
            emit_event(ctx, "remediation.apply", outcome="failed", details={"checks": args.check_ids, "error": str(exc)})
            print(f"ERROR: {exc}", file=sys.stderr)
            return REMEDIATION_FAILED
        if args.dry_run:
            emit_event(ctx, "remediation.dry_run", details={"checks": args.check_ids})
            print("Dry-run/preflight passed: no files or runtime settings were changed.")
            return OK
        emit_event(ctx, "remediation.apply", details={"checks": args.check_ids, "transaction_id": txid})
        print(f"Applied successfully. Transaction: {txid}")
        return OK

    if args.command == "transactions":
        rows = list_transactions(ctx)
        if not rows:
            print("No Aegis transactions found.")
            return OK
        for row in rows:
            print(f"{row['transaction_id']}  {row['created_at']}  {row['description']}")
        return OK

    if args.command == "rollback":
        try:
            result = rollback_transaction(ctx, args.transaction_id, force=args.force, restore_runtime=not args.files_only)
        except (FileNotFoundError, ValueError) as exc:
            emit_event(ctx, "rollback", outcome="failed", details={"transaction_id": args.transaction_id, "error": str(exc)})
            print(f"ERROR: {exc}", file=sys.stderr)
            return USAGE_OR_INPUT
        print("Restored files:")
        for path in result.restored:
            print(f"  {path}")
        if args.files_only:
            emit_event(ctx, "rollback", details={"transaction_id": args.transaction_id, "files_only": True})
            print("Runtime restore skipped by request. Re-apply/validate affected services and sysctls manually.")
            return OK
        if result.runtime_results:
            print("Runtime restore/validation:")
            for item in result.runtime_results:
                print(f"  [{'OK' if item.ok else 'FAIL'}] {item.kind}")
                for message in item.messages:
                    print(f"      {message}")
        if not result.runtime_ok:
            emit_event(ctx, "rollback", outcome="runtime_failed", details={"transaction_id": args.transaction_id})
            print("ERROR: files were restored, but one or more runtime restoration steps failed", file=sys.stderr)
            return RUNTIME_ROLLBACK_FAILED
        emit_event(ctx, "rollback", details={"transaction_id": args.transaction_id})
        print("Rollback complete and known runtime state validated.")
        return OK
    return USAGE_OR_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
