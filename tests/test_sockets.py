from pathlib import Path

from aegis.context import SystemContext
from aegis.inventory.sockets import collect_listening_sockets, parse_ss_output


def test_parse_ss_output_extracts_wildcard_and_process():
    text = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=694,fd=3))\n'
    result = parse_ss_output(text)
    assert len(result) == 1
    assert result[0].wildcard is True
    assert result[0].port == 22
    assert result[0].process == "sshd"
    assert result[0].pid == 694


def test_fake_root_socket_fixture(tmp_path: Path):
    fixture = tmp_path / "var/lib/aegis/fixtures"
    fixture.mkdir(parents=True)
    (fixture / "ss.txt").write_text("tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*\n", encoding="utf-8")
    sockets, source = collect_listening_sockets(SystemContext(tmp_path))
    assert source == "fixture"
    assert sockets[0].port == 6379
