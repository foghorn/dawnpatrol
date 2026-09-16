"""ToolBox and evidence-bundle behaviour for the internal investigation agent."""

from __future__ import annotations

import json

from dawnpatrol.agent.bundle import build_bundle
from dawnpatrol.agent.tools import ToolBox
from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.devices import DeviceDirectory
from dawnpatrol.enrichment.broker import EnrichmentBroker
from dawnpatrol.query import EventQuery


def _toolbox(store, profile, devices=None, run_id="r1"):
    query = EventQuery(store, run_id)
    baseline = Baseline(store, run_id)
    broker = EnrichmentBroker([], store, profile, enabled=False)
    return ToolBox(store=store, query=query, profile=profile, baseline=baseline,
                    broker=broker, signals=[], run_id=run_id, devices=devices)


# --------------------------------------------------------------------------- #
# ToolBox.get_device_directory
# --------------------------------------------------------------------------- #


def test_get_device_directory_lists_all_when_no_ip_given(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog", role="librenms-managed",
                  hostname="edge")
    toolbox = _toolbox(store, profile, devices=devices)
    payload = json.loads(toolbox.get_device_directory({}))
    assert payload["devices"][0]["ip"] == "10.10.0.1"
    assert payload["devices"][0]["hostname"] == "edge"


def test_get_device_directory_detail_for_one_ip(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog", hostname="edge",
                  hardware="ASUS RT-AX88U Pro")
    toolbox = _toolbox(store, profile, devices=devices)
    payload = json.loads(toolbox.get_device_directory({"ip": "10.10.0.1"}))
    assert payload["hostname"] == "edge"
    assert payload["hardware"] == "ASUS RT-AX88U Pro"


def test_get_device_directory_unknown_ip_is_a_clear_error(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog")
    toolbox = _toolbox(store, profile, devices=devices)
    result = toolbox.get_device_directory({"ip": "10.10.0.99"})
    assert "no directory entry" in result
    assert "10.10.0.1" in result


def test_tool_not_registered_when_no_devices_known(store, profile):
    toolbox = _toolbox(store, profile, devices=DeviceDirectory())
    names = {t.name for t in toolbox.specs()}
    assert "get_device_directory" not in names


def test_tool_registered_when_devices_known(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog")
    toolbox = _toolbox(store, profile, devices=devices)
    names = {t.name for t in toolbox.specs()}
    assert "get_device_directory" in names


# --------------------------------------------------------------------------- #
# build_bundle's DEVICE DIRECTORY section
# --------------------------------------------------------------------------- #


def test_bundle_includes_device_directory_section(window, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog", role="librenms-managed",
                  hostname="edge", hardware="ASUS RT-AX88U Pro")
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[], signals=[],
        notes=[], watchlist=[], enrichment_budgets={}, baseline_available=False,
        run_id="r1", devices=devices,
    )
    assert "DEVICE DIRECTORY" in bundle
    assert "10.10.0.1" in bundle
    assert "edge" in bundle


def test_bundle_omits_device_directory_section_when_empty(window, profile):
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[], signals=[],
        notes=[], watchlist=[], enrichment_budgets={}, baseline_available=False,
        run_id="r1", devices=DeviceDirectory(),
    )
    assert "DEVICE DIRECTORY" not in bundle


def test_bundle_works_without_devices_argument_at_all(window, profile):
    """devices is optional - callers that predate this feature still work."""
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[], signals=[],
        notes=[], watchlist=[], enrichment_budgets={}, baseline_available=False,
        run_id="r1",
    )
    assert "DEVICE DIRECTORY" not in bundle
