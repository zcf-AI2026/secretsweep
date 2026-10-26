import json

import pytest

from secretsweep.engine import PlaceholderMap, Sweeper, read_text, redact, restore, scan, write_text
from secretsweep.rules import load_config


@pytest.fixture()
def sweeper():
    return Sweeper(load_config(None))


def redact_text(sweeper, text, pmap=None):
    pmap = pmap or PlaceholderMap(sweeper.config)
    new_text, count = sweeper.redact_text(text, pmap)
    return new_text, count, pmap


# --- detection -------------------------------------------------------------

def test_finds_private_ip_phone_and_email(sweeper):
    text = "db at 10.1.2.3, call 13800138000, mail ops@example.com"
    hits = sweeper.scan_text(text)
    assert {h.rule_id for h in hits} == {"ipv4_private", "phone_cn", "email"}


def test_public_and_private_ip_are_different_rules(sweeper):
    hits = sweeper.scan_text("192.168.1.5 vs 203.0.113.9")
    rules = {h.rule_id for h in hits}
    assert rules == {"ipv4_private", "ipv4_public"}


def test_line_numbers_are_reported(sweeper):
    hits = sweeper.scan_text("first\nsecond 10.0.0.9\n")
    assert hits[0].line == 2


def test_allow_list_suppresses_values(tmp_path):
    config_file = tmp_path / "cfg.toml"
    config_file.write_text('[settings]\nallow = ["10.0.0.9"]\n', encoding="utf-8")
    sweeper = Sweeper(load_config(config_file))
    assert sweeper.scan_text("host 10.0.0.9 and 10.0.0.10")[0].value == "10.0.0.10"


def test_longest_match_wins_on_overlap(sweeper):
    # A connection string carries a password *and* an IP; only the URL is replaced.
    text = "postgres://admin:hunter2@10.1.2.3:5432/app"
    new_text, count, _ = redact_text(sweeper, text)
    assert count == 1
    assert new_text == "⟨DB_URL⟩"


# --- redaction -------------------------------------------------------------

def test_redact_replaces_and_records_mapping(sweeper):
    new_text, count, pmap = redact_text(sweeper, "host 10.1.2.3 ok")
    assert new_text == "host ⟨PRIVATE_IP⟩ ok"
    assert count == 1
    assert pmap.entries == [
        {"rule": "ipv4_private", "value": "10.1.2.3", "placeholder": "⟨PRIVATE_IP⟩"}
    ]


def test_second_distinct_value_gets_a_numbered_placeholder(sweeper):
    new_text, _, _ = redact_text(sweeper, "10.1.2.3 and 10.1.2.4")
    assert new_text == "⟨PRIVATE_IP⟩ and ⟨PRIVATE_IP_2⟩"


def test_same_value_is_stable_across_files(sweeper, tmp_path):
    a, b = tmp_path / "a.md", tmp_path / "b.md"
    a.write_text("10.1.2.3", encoding="utf-8")
    b.write_text("10.1.2.3", encoding="utf-8")
    pmap = PlaceholderMap(sweeper.config)
    redact([str(tmp_path)], sweeper, pmap)
    assert read_text(a) == read_text(b) == "⟨PRIVATE_IP⟩"
    assert len(pmap.entries) == 1


def test_redact_is_idempotent(sweeper, tmp_path):
    target = tmp_path / "note.md"
    target.write_text("host 10.1.2.3", encoding="utf-8")
    pmap = PlaceholderMap(sweeper.config)
    redact([str(target)], sweeper, pmap)
    first = read_text(target)
    changed, count = redact([str(target)], sweeper, pmap)
    assert (changed, count) == (0, 0)
    assert read_text(target) == first


def test_dry_run_changes_nothing(sweeper, tmp_path):
    target = tmp_path / "note.md"
    target.write_text("host 10.1.2.3", encoding="utf-8")
    changed, count = redact([str(target)], sweeper, PlaceholderMap(sweeper.config), dry_run=True)
    assert (changed, count) == (1, 1)
    assert read_text(target) == "host 10.1.2.3"


def test_restore_roundtrip(sweeper, tmp_path):
    target = tmp_path / "note.md"
    original = "db 10.1.2.3 user ops@example.com\n"
    target.write_text(original, encoding="utf-8")
    pmap = PlaceholderMap(sweeper.config)
    redact([str(target)], sweeper, pmap)
    assert "10.1.2.3" not in read_text(target)
    restore([str(target)], pmap)
    assert read_text(target) == original


def test_mapping_file_roundtrips(sweeper, tmp_path):
    map_path = tmp_path / "map.json"
    pmap = PlaceholderMap(sweeper.config)
    pmap.get("ipv4_private", "PRIVATE_IP", "10.1.2.3")
    pmap.save(map_path)
    assert json.loads(map_path.read_text())["entries"][0]["value"] == "10.1.2.3"
    reloaded = PlaceholderMap.load(map_path, sweeper.config)
    # An existing value keeps its placeholder instead of being renumbered.
    assert reloaded.get("ipv4_private", "PRIVATE_IP", "10.1.2.3") == "⟨PRIVATE_IP⟩"
    assert reloaded.get("ipv4_private", "PRIVATE_IP", "10.1.2.4") == "⟨PRIVATE_IP_2⟩"


# --- file walking ----------------------------------------------------------

def test_skips_binary_and_unknown_extensions(sweeper, tmp_path):
    (tmp_path / "note.md").write_text("10.1.2.3", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02 10.1.2.3")
    hits = scan([str(tmp_path)], sweeper)
    assert [h.path for h in hits] == [str(tmp_path / "note.md")]


def test_skips_noise_directories(sweeper, tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.md").write_text("10.1.2.3", encoding="utf-8")
    assert scan([str(tmp_path)], sweeper) == []


def test_exclude_glob(sweeper, tmp_path):
    (tmp_path / "keep.md").write_text("10.1.2.3", encoding="utf-8")
    (tmp_path / "skip.md").write_text("10.1.2.4", encoding="utf-8")
    hits = scan([str(tmp_path)], sweeper, excludes=["skip.md"])
    assert [h.value for h in hits] == ["10.1.2.3"]


def test_line_endings_are_preserved(sweeper, tmp_path):
    target = tmp_path / "crlf.md"
    target.write_bytes(b"host 10.1.2.3\r\nnext\r\n")
    redact([str(target)], sweeper, PlaceholderMap(sweeper.config))
    assert target.read_bytes() == "host ⟨PRIVATE_IP⟩\r\nnext\r\n".encode()


# --- config ----------------------------------------------------------------

def test_custom_rule_is_added(tmp_path):
    config_file = tmp_path / "cfg.toml"
    config_file.write_text(
        "[[rule]]\nid = \"ticket\"\npattern = '''TICKET-\\d{6}'''\nplaceholder = \"TICKET\"\n",
        encoding="utf-8",
    )
    sweeper = Sweeper(load_config(config_file))
    assert sweeper.scan_text("see TICKET-123456")[0].rule_id == "ticket"


def test_custom_rule_overrides_builtin(tmp_path):
    config_file = tmp_path / "cfg.toml"
    config_file.write_text(
        "[[rule]]\nid = \"ipv4_public\"\npattern = '''never-matches-this'''\nplaceholder = \"X\"\n",
        encoding="utf-8",
    )
    sweeper = Sweeper(load_config(config_file))
    assert sweeper.scan_text("203.0.113.9") == []


def test_custom_placeholder_format(tmp_path):
    config_file = tmp_path / "cfg.toml"
    config_file.write_text('[settings]\nplaceholder_format = "<<{name}>>"\n', encoding="utf-8")
    sweeper = Sweeper(load_config(config_file))
    text, _, _ = redact_text(sweeper, "10.1.2.3")
    assert text == "<<PRIVATE_IP>>"


def test_unknown_rule_key_is_rejected(tmp_path):
    from secretsweep.rules import ConfigError

    config_file = tmp_path / "cfg.toml"
    config_file.write_text(
        "[[rule]]\nid = \"a\"\npattern = '''x'''\nplaceholder = \"A\"\nbogus = 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(config_file)


def test_write_text_keeps_content(tmp_path):
    target = tmp_path / "x.md"
    write_text(target, "中文 ⟨PRIVATE_IP⟩\n")
    assert read_text(target) == "中文 ⟨PRIVATE_IP⟩\n"
