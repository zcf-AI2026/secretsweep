import json

from secretsweep.cli import main


def test_scan_exit_code_is_zero(tmp_path, capsys):
    (tmp_path / "note.md").write_text("host 10.1.2.3\n", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "ipv4_private" in out
    assert "10.***" in out  # value is masked in the report


def test_check_fails_when_findings_exist(tmp_path, capsys):
    (tmp_path / "note.md").write_text("host 10.1.2.3\n", encoding="utf-8")
    assert main(["check", str(tmp_path)]) == 1
    assert "Fail" in capsys.readouterr().err


def test_check_passes_when_clean(tmp_path, capsys):
    (tmp_path / "note.md").write_text("nothing to see here\n", encoding="utf-8")
    assert main(["check", str(tmp_path)]) == 0
    assert "Clean" in capsys.readouterr().out


def test_json_format(tmp_path, capsys):
    (tmp_path / "note.md").write_text("host 10.1.2.3\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["rule_id"] == "ipv4_private"


def test_apply_then_restore(tmp_path, capsys):
    note = tmp_path / "note.md"
    note.write_text("host 10.1.2.3\n", encoding="utf-8")
    map_file = tmp_path / "map.json"
    assert main(["apply", str(tmp_path), "-m", str(map_file)]) == 0
    assert note.read_text(encoding="utf-8") == "host ⟨PRIVATE_IP⟩\n"
    assert map_file.exists()
    assert main(["restore", str(tmp_path), "-m", str(map_file)]) == 0
    assert note.read_text(encoding="utf-8") == "host 10.1.2.3\n"


def test_restore_without_mapping_errors(tmp_path, capsys):
    assert main(["restore", str(tmp_path), "-m", str(tmp_path / "nope.json")]) == 2
    assert "not found" in capsys.readouterr().err


def test_init_writes_starter_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert (tmp_path / "secretsweep.toml").exists()
    assert main(["init"]) == 2  # refuses to clobber
    assert main(["init", "--force"]) == 0


def test_rules_lists_ids(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "ipv4_private" in out and "private_key" in out


def test_bad_config_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[[rule]]\nid = ", encoding="utf-8")
    assert main(["scan", str(tmp_path), "-c", str(bad)]) == 2
    assert "secretsweep:" in capsys.readouterr().err


def test_mapping_file_is_never_swept(tmp_path):
    """A map stored inside the target directory must survive apply + restore."""
    note = tmp_path / "note.md"
    note.write_text("host 10.1.2.3 and 10.1.2.4\n", encoding="utf-8")
    map_file = tmp_path / "map.json"
    assert main(["apply", str(tmp_path), "-m", str(map_file)]) == 0
    saved = json.loads(map_file.read_text(encoding="utf-8"))
    assert main(["restore", str(tmp_path), "-m", str(map_file)]) == 0
    assert note.read_text(encoding="utf-8") == "host 10.1.2.3 and 10.1.2.4\n"
    # untouched: still the same valid mapping we wrote
    assert json.loads(map_file.read_text(encoding="utf-8")) == saved
