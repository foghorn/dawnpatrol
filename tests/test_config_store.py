"""Configuration resolution, secret handling, and persistence."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from dawnpatrol.config import DatabaseSettings, Settings
from dawnpatrol.models import UTC, EntityType
from dawnpatrol.profile import Profile
from dawnpatrol.secrets import SecretRegistry, SecretStr, read_env

# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


def test_secret_never_renders_itself():
    s = SecretStr("hunter2-super-secret")
    assert "hunter2" not in repr(s)
    assert "hunter2" not in str(s)
    assert "hunter2" not in f"{s}"
    assert s.get() == "hunter2-super-secret"


def test_file_variant_wins_over_env(tmp_path, monkeypatch):
    """An explicit secrets mount is a stronger signal than an inherited env var."""
    path = tmp_path / "secret"
    path.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("TEST_TOKEN", "from-env")
    monkeypatch.setenv("TEST_TOKEN_FILE", str(path))
    assert read_env("TEST_TOKEN") == "from-file"


def test_missing_secret_file_fails_loudly(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_TOKEN_FILE", str(tmp_path / "nope"))
    with pytest.raises(FileNotFoundError):
        read_env("TEST_TOKEN")


def test_registry_detects_and_redacts_leaks():
    r = SecretRegistry()
    r.register(SecretStr("supersecrettoken123"))
    r.register("x")   # too short to match safely; ignored
    assert r.scan("all fine here") == []
    assert r.scan("token=supersecrettoken123") != []
    assert "supersecrettoken123" not in r.redact("token=supersecrettoken123")


# --------------------------------------------------------------------------- #
# Database selection
# --------------------------------------------------------------------------- #


def test_sqlite_is_the_default(tmp_path, monkeypatch):
    for var in list(os_environ_keys()):
        monkeypatch.delenv(var, raising=False)
    db = DatabaseSettings.from_env(tmp_path, SecretRegistry())
    assert db.dialect == "sqlite"
    assert db.url.startswith("sqlite:///")


def test_mysql_is_selected_when_credentials_appear(tmp_path, monkeypatch):
    """Credential-driven override: no flag to remember to flip."""
    monkeypatch.setenv("DAWNPATROL_DB_HOST", "db.internal")
    monkeypatch.setenv("DAWNPATROL_DB_USER", "dawnpatrol")
    monkeypatch.setenv("DAWNPATROL_DB_PASSWORD", "p@ss word/special")
    monkeypatch.setenv("DAWNPATROL_DB_NAME", "nw")
    db = DatabaseSettings.from_env(tmp_path, SecretRegistry())
    assert db.dialect == "mysql"
    assert db.url.startswith("mysql+pymysql://dawnpatrol:")
    assert "db.internal:3306/nw" in db.url
    assert "p%40ss+word%2Fspecial" in db.url   # URL-encoded, not raw


def test_mysql_password_is_masked_in_the_display_string(tmp_path, monkeypatch):
    monkeypatch.setenv("DAWNPATROL_DB_HOST", "db.internal")
    monkeypatch.setenv("DAWNPATROL_DB_USER", "dawnpatrol")
    monkeypatch.setenv("DAWNPATROL_DB_PASSWORD", "supersecret")
    db = DatabaseSettings.from_env(tmp_path, SecretRegistry())
    assert "supersecret" not in db.display
    assert "***" in db.display


def test_host_without_user_falls_back_to_sqlite(tmp_path, monkeypatch):
    monkeypatch.setenv("DAWNPATROL_DB_HOST", "db.internal")
    monkeypatch.delenv("DAWNPATROL_DB_USER", raising=False)
    assert DatabaseSettings.from_env(tmp_path, SecretRegistry()).dialect == "sqlite"


def os_environ_keys():
    import os
    return [k for k in os.environ if k.startswith("DAWNPATROL_DB")]


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #


def test_window_defaults_to_24_hours(monkeypatch, tmp_path):
    monkeypatch.delenv("DAWNPATROL_WINDOW_HOURS", raising=False)
    monkeypatch.setenv("DAWNPATROL_DATA_DIR", str(tmp_path))
    assert Settings.from_env().window_hours == 24


def test_window_is_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("DAWNPATROL_WINDOW_HOURS", "72")
    monkeypatch.setenv("DAWNPATROL_DATA_DIR", str(tmp_path))
    assert Settings.from_env().window_hours == 72


def test_retention_defaults_and_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("DAWNPATROL_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("DAWNPATROL_RETENTION_RAW_DAYS", raising=False)
    assert Settings.from_env().retention.raw_days == 7
    monkeypatch.setenv("DAWNPATROL_RETENTION_RAW_DAYS", "30")
    assert Settings.from_env().retention.raw_days == 30


def test_explicit_allowlist_overrides_auto_enable(settings):
    settings.enabled_sources = ["only_this"]
    assert settings.allowed("source", "only_this")
    assert not settings.allowed("source", "something_else")


def test_disable_list_always_wins(settings):
    settings.enabled_sources = ["thing"]
    settings.disabled = ["thing"]
    assert not settings.allowed("source", "thing")


# --------------------------------------------------------------------------- #
# Profile
# --------------------------------------------------------------------------- #


def test_empty_profile_is_valid():
    p = Profile.load(None)
    assert p.site_name == "network"
    assert p.zone_of("10.0.0.1") == "private"


def test_zone_resolution(profile):
    assert profile.zone_of("10.10.0.5") == "lan"
    assert profile.zone_of("10.10.50.7") == "iot"
    assert profile.zone_of("8.8.8.8") == "external"
    assert profile.zone_of("172.16.4.4") == "private"
    assert profile.zone_of("not-an-ip") is None


def test_external_and_routable_are_different(profile):
    """Documentation ranges are external but not routable - the canaries rely
    on this, and enrichment must never submit them."""
    assert profile.is_external("203.0.113.45")
    assert not profile.is_routable("203.0.113.45")
    assert profile.is_external("8.8.8.8")
    assert profile.is_routable("8.8.8.8")
    assert not profile.is_external("10.10.0.5")


def test_attribution_caveat_only_for_nat_gateways(profile):
    caveat = profile.attribution_caveat("10.10.0.8")
    assert "NATed" in caveat and "iot" in caveat
    assert profile.attribution_caveat("10.10.0.5") == ""


def test_benign_domain_matching(profile):
    assert profile.is_benign_domain("google.com")
    assert profile.is_benign_domain("mail.google.com")
    assert not profile.is_benign_domain("notgoogle.com")
    assert not profile.is_benign_domain("evil.example.net")


def test_profile_context_contains_no_volatile_content(profile):
    text = profile.as_context()
    assert "testnet" in text and "iot" in text
    assert "malformed mDNS" in text     # known quirks are carried through
    assert str(datetime.now(UTC).year) not in text


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #


def test_entity_baseline_tracks_first_seen(store):
    now = datetime.now(UTC)
    store.observe_entities([(EntityType.DOMAIN, "a.example", 5)], now)
    store.observe_entities([(EntityType.DOMAIN, "a.example", 3)], now)
    info = store.entity_info("a.example")
    assert info["occurrences"] == 8


def test_novelty_detection(store):
    from dawnpatrol.analyzers.baseline import Baseline
    old = datetime.now(UTC) - timedelta(days=10)
    store.observe_entities([(EntityType.DOMAIN, "known.example", 1)], old)
    b = Baseline(store, "run")
    novel = b.novel(EntityType.DOMAIN, ["known.example", "brand-new.example"])
    assert novel == ["brand-new.example"]


def test_entity_pairs_from_events_tracks_device_by_mac():
    """A MAC in Event.user (DHCP leases, Wi-Fi deauth) becomes an
    EntityType.DEVICE entity - a device identity that survives DHCP lease
    renewal, unlike its IP."""
    from dawnpatrol.models import Event, EventKind
    from dawnpatrol.store import entity_pairs_from_events

    events = [
        Event(ts=datetime.now(UTC), source="librenms_syslog", kind=EventKind.SYSTEM,
              dedup_key="e1", action="dhcpack", src_ip="10.10.0.5",
              user="aa:bb:cc:dd:ee:ff"),
        Event(ts=datetime.now(UTC), source="librenms_syslog", kind=EventKind.SYSTEM,
              dedup_key="e2", action="dhcpack", src_ip="10.10.0.6",
              user="aa:bb:cc:dd:ee:ff"),
    ]
    pairs = entity_pairs_from_events(events)
    device_pairs = {(t, v): c for t, v, c in pairs if t == EntityType.DEVICE}
    assert device_pairs[(EntityType.DEVICE, "aa:bb:cc:dd:ee:ff")] == 2


def test_enrichment_cache_respects_ttl(store):
    store.cache_put("x", "1.2.3.4", {"score": 10}, timedelta(seconds=60))
    assert store.cache_get("x", "1.2.3.4") == {"score": 10}
    store.cache_put("x", "5.6.7.8", {"score": 20}, timedelta(seconds=-1))
    assert store.cache_get("x", "5.6.7.8") is None


def test_suppression_lifecycle(store):
    sid = store.add_suppression({"taxonomy": "t"}, "reason", "me", 30)
    assert any(s["id"] == sid for s in store.active_suppressions())
    assert store.delete_suppression(sid)
    assert not any(s["id"] == sid for s in store.active_suppressions())


def test_expired_suppression_is_inactive(store):
    store.add_suppression({"taxonomy": "t"}, "r", "me", expires_days=None)
    assert len(store.active_suppressions()) == 1


def test_watchlist_expiry(store):
    store.add_watch("ip", "1.2.3.4", "watch me", "run1", expires_days=7)
    assert len(store.active_watchlist()) == 1
    store.add_watch("ip", "1.2.3.4", "updated", "run2", expires_days=7)
    items = store.active_watchlist()
    assert len(items) == 1 and items[0]["reason"] == "updated"


def test_notebook_entries_round_trip_in_order(store):
    store.add_notebook_entry("first note", author="alice")
    store.add_notebook_entry("second note", author="bob")
    entries = store.list_notebook_entries()
    assert [e["text"] for e in entries] == ["first note", "second note"]
    assert entries[0]["author"] == "alice"


def test_recent_notebook_entries_caps_and_keeps_chronological_order(store):
    for i in range(5):
        store.add_notebook_entry(f"note {i}")
    recent = store.recent_notebook_entries(2)
    assert [e["text"] for e in recent] == ["note 3", "note 4"]


def test_notebook_entry_delete_lifecycle(store):
    entry_id = store.add_notebook_entry("stale note")
    assert any(e["id"] == entry_id for e in store.list_notebook_entries())
    assert store.delete_notebook_entry(entry_id)
    assert not any(e["id"] == entry_id for e in store.list_notebook_entries())
    assert not store.delete_notebook_entry(entry_id)


def test_busy_timeout_applies_to_every_pooled_connection_not_just_the_first(store):
    """Regression test for a real "database is locked" hit in production: the
    MCP server and the scheduler pull connections from the same engine's pool
    concurrently, from different threads, so a PRAGMA applied once at Store
    construction (to whichever single connection happened to be open then)
    left every other pooled connection at SQLite's default busy_timeout=0 -
    an ordinary write held during a large batch insert made a concurrent
    writer fail immediately instead of waiting a bounded, harmless amount."""
    seen_timeouts = []
    for _ in range(3):
        with store.engine.connect() as conn:
            # Force the pool to hand back a *new* underlying DBAPI connection
            # each time, rather than reusing one already configured by
            # Store.__init__ - invalidate() drops it from the pool entirely.
            conn.connection.invalidate()
        with store.engine.connect() as conn:
            value = conn.exec_driver_sql("PRAGMA busy_timeout").scalar()
            seen_timeouts.append(value)

    assert all(t == 30000 for t in seen_timeouts), (
        f"expected every fresh connection to report busy_timeout=30000, got {seen_timeouts}"
    )


def test_a_write_waits_out_a_concurrent_long_transaction_instead_of_failing(store):
    """The same fix, exercised as an actual lock: a write held open in one
    thread must not fail a concurrent write in another, it must wait for it."""
    import threading
    import time

    holder_ready = threading.Event()
    release_holder = threading.Event()

    def hold_a_write_transaction() -> None:
        with store.engine.begin() as conn:
            conn.exec_driver_sql(
                "INSERT INTO notebook (created_at, author, text) "
                "VALUES (datetime('now'), 'holder', 'in-transaction')"
            )
            holder_ready.set()
            release_holder.wait(timeout=5)

    holder = threading.Thread(target=hold_a_write_transaction)
    holder.start()
    assert holder_ready.wait(timeout=5), "holder thread never started its transaction"

    threading.Timer(0.5, release_holder.set).start()

    start = time.monotonic()
    try:
        entry_id = store.add_notebook_entry("competing write")
    finally:
        holder.join(timeout=5)

    elapsed = time.monotonic() - start
    assert entry_id  # succeeded rather than raising "database is locked"
    assert elapsed > 0.2, "the write returned suspiciously fast for one that had to wait"


def test_readonly_sql_executes(store, window):
    store.start_run("r1", 1, window.start, window)
    cols, rows = store.readonly_sql("SELECT 1 AS n")
    assert cols == ["n"] and rows == [[1]]
