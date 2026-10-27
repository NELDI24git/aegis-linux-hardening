from pathlib import Path

import pytest

from aegis.context import SystemContext
from aegis.engine.transaction import Transaction, rollback_transaction


def test_transaction_restores_existing_file(tmp_path: Path):
    ctx = SystemContext(tmp_path)
    target = ctx.path("/etc/example.conf")
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    tx = Transaction(ctx)
    tx.backup("/etc/example.conf")
    tx.atomic_write("/etc/example.conf", "after\n")
    tx.commit_manifest()

    result = rollback_transaction(ctx, tx.transaction_id)
    assert result.restored == ["/etc/example.conf"]
    assert target.read_text(encoding="utf-8") == "before\n"


def test_transaction_removes_new_file_on_rollback(tmp_path: Path):
    ctx = SystemContext(tmp_path)
    tx = Transaction(ctx)
    tx.backup("/etc/new.conf")
    tx.atomic_write("/etc/new.conf", "created\n")
    tx.commit_manifest()

    result = rollback_transaction(ctx, tx.transaction_id)
    assert result.restored == ["/etc/new.conf"]
    assert not ctx.path("/etc/new.conf").exists()


def test_rollback_refuses_to_overwrite_newer_admin_edit(tmp_path: Path):
    ctx = SystemContext(tmp_path)
    target = ctx.path("/etc/example.conf")
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    tx = Transaction(ctx)
    tx.backup("/etc/example.conf")
    tx.atomic_write("/etc/example.conf", "aegis\n")
    tx.commit_manifest()
    target.write_text("administrator changed this later\n", encoding="utf-8")

    with pytest.raises(ValueError, match="changed after transaction"):
        rollback_transaction(ctx, tx.transaction_id)

    result = rollback_transaction(ctx, tx.transaction_id, force=True)
    assert result.runtime_ok
    assert target.read_text(encoding="utf-8") == "before\n"
