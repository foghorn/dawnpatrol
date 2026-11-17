"""IoC lists: loading (both formats, defanging, tiers, expiry, unobservable
types), matching (exact, CIDR, subdomain, suffix), the per-run analyzer's
severity rules, and the retained-history sweep."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.ioc_match import IocMatchAnalyzer
from dawnpatrol.iocs import ioc_paths, load_iocs
from dawnpatrol.models import Event, EventKind, Severity
from dawnpatrol.query import EventQuery

# Shaped like the MalwareMustDie ARTEX list: defanged values, tiers, expiry,
# and rows of types a network sensor cannot see.
MMD_CSV = """indicator,type,tier,class,source_level,source,source_url,first_seen,valid_from,valid_until,campaign,notes,warning,durability,alert_until,hunt_until
198.51.100[.]7,ipv4,T3,C,V,Vendor A,https://x.example,2026-10-01,2026-10-01,2027-11-13,Campaign One,,may be reassigned,low,2099-01-01,2099-01-01
203.0.113.0/24,ipv4-cidr,T4,C,V,Vendor B,https://x.example,2026-10-01,2026-10-01,2027-11-13,Campaign Two,,never act alone,low,2099-01-01,2099-01-01
bad[.]example,domain,T3,C,V,Vendor A,https://x.example,2026-10-01,2026-10-01,2027-11-13,Campaign One,,,low,2099-01-01,2099-01-01
oast.example,domain-suffix,T4,C,V,Vendor C,https://x.example,2026-10-01,2026-10-01,2027-11-13,Generic,,,low,2099-01-01,2099-01-01
192.0.2.99,ipv4,T3,C,V,Vendor A,https://x.example,2026-10-01,2026-10-01,2027-11-13,Old,,,low,2020-01-01,2020-01-01
Mozilla/5.0 (evil),user-agent,T2,C,V,Vendor A,https://x.example,2026-10-01,2026-10-01,2027-11-13,UA,,,low,2099-01-01,2099-01-01
x/image,container-image,T1,C,V,Vendor A,https://x.example,2026-10-01,2026-10-01,2027-11-13,Img,,,low,2099-01-01,2099-01-01
"""


@pytest.fixture
def ioc_dir(tmp_path):
    d = tmp_path / "iocs"
    d.mkdir()
    (d / "mmd.csv").write_text(MMD_CSV, encoding="utf-8")
    (d / "plain.txt").write_text(
        "# a bare list\n198.51.100.200\n*.suffix.example  # comment\nhxxp://plain[.]example/x\n",
        encoding="utf-8")
    (d / "ignored.json").write_text("{}", encoding="utf-8")
    return d


@pytest.fixture
def iocs(ioc_dir):
    return load_iocs(ioc_paths(str(ioc_dir)))


def test_lists_load_with_tiers_defanging_expiry_and_skipped_types(iocs):
    by_value = {i.value: i for i in iocs.indicators}
    assert by_value["198.51.100.7"].severity == Severity.MEDIUM          # T3, refanged
    assert by_value["203.0.113.0/24"].kind == "cidr"
    assert by_value["203.0.113.0/24"].severity == Severity.LOW          # T4
    assert by_value["bad.example"].kind == "domain"
    assert by_value["oast.example"].kind == "domain_suffix"
    assert "192.0.2.99" not in by_value                                 # past alert_until
    assert iocs.expired == 1
    assert iocs.skipped_types == {"user-agent": 1, "container-image": 1}
    # Plain text: inferred types, comments, defanged URL reduced to its host.
    assert by_value["198.51.100.200"].severity == Severity.LOW
    assert by_value["suffix.example"].kind == "domain_suffix"
    assert by_value["plain.example"].kind == "domain"
    assert sorted(iocs.files) == ["mmd.csv", "plain.txt"]


def test_overbroad_ranges_and_garbage_are_rejected(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("0.0.0.0/0\n10.0.0.0/4\nnot a thing!\n", encoding="utf-8")
    loaded = load_iocs([f])
    assert loaded.indicators == []
    assert loaded.invalid == 3


def test_expiry_uses_the_given_day(tmp_path):
    f = tmp_path / "x.csv"
    f.write_text("indicator,type,alert_until\n198.51.100.1,ipv4,2026-06-01\n", encoding="utf-8")
    assert len(load_iocs([f], today=date(2026, 6, 1)).indicators) == 1
    assert len(load_iocs([f], today=date(2026, 6, 2)).indicators) == 0


def test_matching_covers_exact_cidr_subdomain_and_suffix(iocs):
    ips = iocs.match_ips(["198.51.100.7", "203.0.113.77", "198.51.100.8", "junk"])
    assert set(ips) == {"198.51.100.7", "203.0.113.77"}
    doms = iocs.match_domains(["bad.example", "a.b.bad.example", "notbad.example",
                               "x.oast.example", "oast.example", "Suffix.Example."])
    assert set(doms) == {"bad.example", "a.b.bad.example", "x.oast.example",
                         "oast.example", "Suffix.Example."}


# --------------------------------------------------------------------------- #
# The per-run analyzer
# --------------------------------------------------------------------------- #

def _fw(window, n, **kw):
    return Event(ts=window.end - timedelta(minutes=5), source="synthetic",
                 kind=EventKind.FIREWALL, dedup_key=f"fw{n}", proto="tcp", **kw)


def _dns(window, n, **kw):
    return Event(ts=window.end - timedelta(minutes=5), source="synthetic",
                 kind=EventKind.DNS, dedup_key=f"dns{n}", **kw)


def _run(store, profile, window, iocs, events):
    store.start_run("ioc", 1, window.start, window)
    store.insert_events("ioc", events)
    q = EventQuery(store, "ioc")
    return IocMatchAnalyzer(iocs).run(q, profile, Baseline(store, "ioc"))


def test_blocked_inbound_probe_is_capped_at_low(store, profile, window, iocs):
    result = _run(store, profile, window, iocs, [
        _fw(window, 1, action="drop", src_ip="198.51.100.7", dst_ip="10.10.0.1", dst_port=443),
        _fw(window, 2, action="drop", src_ip="198.51.100.7", dst_ip="10.10.0.1", dst_port=8080),
    ])
    (sig,) = result.signals
    assert sig.id == "ioc.ip.198.51.100.7"
    assert sig.severity_hint == Severity.LOW
    assert sig.evidence["inbound_blocked"] == 2 and sig.evidence["inbound_accepted"] == 0
    assert sorted(sig.evidence["dst_ports"]) == [443, 8080]
    assert "capped" in sig.evidence["severity_note"]
    assert sig.evidence["tier"] == "T3" and sig.evidence["campaign"] == "Campaign One"


def test_internal_host_reaching_out_keeps_the_list_severity(store, profile, window, iocs):
    result = _run(store, profile, window, iocs, [
        _fw(window, 1, action="accept", src_ip="10.10.50.20", dst_ip="198.51.100.7",
            dst_port=443),
    ])
    (sig,) = result.signals
    assert sig.severity_hint == Severity.MEDIUM
    assert sig.evidence["outbound_allowed"] == 1
    assert {"ip": "10.10.50.20", "zone": "iot"} in sig.evidence["local_addresses"]
    assert "internal host" in sig.title


def test_accepted_inbound_keeps_the_list_severity(store, profile, window, iocs):
    result = _run(store, profile, window, iocs, [
        _fw(window, 1, action="accept", src_ip="198.51.100.7", dst_ip="10.10.15.5",
            dst_port=443),
    ])
    assert result.signals[0].severity_hint == Severity.MEDIUM


def test_cidr_and_domain_lookups_are_matched(store, profile, window, iocs):
    result = _run(store, profile, window, iocs, [
        _fw(window, 1, action="drop", src_ip="203.0.113.9", dst_ip="10.10.0.1", dst_port=22),
        _dns(window, 2, client_ip="10.10.0.30", domain="cdn.bad.example", blocked=False),
        _dns(window, 3, client_ip="10.10.0.31", domain="cdn.bad.example", blocked=True),
        _dns(window, 4, client_ip="10.10.0.30", domain="fine.example", blocked=False),
    ])
    by_id = {s.id: s for s in result.signals}
    assert set(by_id) == {"ioc.cidr.203.0.113.0/24", "ioc.domain.bad.example"}
    assert by_id["ioc.cidr.203.0.113.0/24"].evidence["matched"] == ["203.0.113.9"]
    dom = by_id["ioc.domain.bad.example"]
    assert dom.severity_hint == Severity.MEDIUM
    assert dom.evidence["queries"] == 2 and dom.evidence["blocked_by_resolver"] == 1
    assert dom.evidence["clients"] == ["10.10.0.30", "10.10.0.31"]


def test_clean_run_has_no_signals_but_reports_what_was_checked(store, profile, window, iocs):
    result = _run(store, profile, window, iocs, [
        _fw(window, 1, action="drop", src_ip="192.0.2.50", dst_ip="10.10.0.1", dst_port=22),
    ])
    assert result.signals == []
    metrics = {m.key: m.value for m in result.metrics}
    assert metrics["ioc.matched"] == 0 and metrics["ioc.indicators"] == len(iocs.indicators)
    assert any("IoC lists:" in n for n in result.notes)


def test_no_lists_means_no_output(store, profile, window, tmp_path, monkeypatch):
    monkeypatch.setenv("DAWNPATROL_IOC_PATHS", str(tmp_path / "missing"))
    store.start_run("ioc", 1, window.start, window)
    result = IocMatchAnalyzer().run(EventQuery(store, "ioc"), profile, Baseline(store, "ioc"))
    assert result.signals == [] and result.metrics == [] and result.notes == []


# --------------------------------------------------------------------------- #
# Retained-history sweep
# --------------------------------------------------------------------------- #

def test_history_sweep_finds_indicators_published_after_the_fact(store, window, iocs):
    day = window.end
    store.save_ioc_flow("old", day, [("198.51.100.7", "203.0.113.10", 8080, "tcp", 1),
                                     ("192.0.2.1", "203.0.113.10", 22, "tcp", 4)])
    store.save_ioc_dns("old", day, [("10.10.0.30", "x.oast.example", 2, 0)])
    ips, domains = store.history_values(days=36500)
    assert iocs.match_ips(ips).keys() >= {"198.51.100.7", "203.0.113.10"}
    hits = iocs.match_domains(domains)
    assert set(hits) == {"x.oast.example"}
    rows = store.history_for(["198.51.100.7"], ["x.oast.example"], days=36500)
    assert {r.get("src_ip") for r in rows} >= {"198.51.100.7"}
    assert any(r.get("domain") == "x.oast.example" and r["queries"] == 2 for r in rows)
