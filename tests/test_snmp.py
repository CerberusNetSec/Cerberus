"""SNMP client, poller and topology tests, run against the fake agents in tools/snmp_sim.py."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus import snmp  # noqa: E402
from cerberus.snmp_poller import diff_neighbors, parse_target, poll_device  # noqa: E402
from cerberus.topology import build_topology, norm_port  # noqa: E402
from tools import snmp_sim  # noqa: E402


# --- BER ------------------------------------------------------------------------
def test_request_matches_reference_bytes():
    # A v2c GET of sysDescr.0, community "public", request-id 1 - checked by hand against RFC 3416 / X.690.
    expected = bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")
    assert snmp.encode_request(snmp.GET, 1, "public", [snmp.oid("1.3.6.1.2.1.1.1.0")]) == expected
    msg = snmp.decode_message(expected)
    assert (msg["version"], msg["community"], msg["pdu"], msg["request_id"]) == (1, b"public", snmp.GET, 1)
    assert msg["varbinds"] == [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)]


def test_ber_edge_cases():
    assert snmp._int(127) == b"\x02\x01\x7f" and snmp._int(128) == b"\x02\x02\x00\x80"
    assert snmp._int(-1) == b"\x02\x01\xff" and snmp._int(0) == b"\x02\x01\x00"
    big = snmp.oid("1.0.8802.1.1.2.1.4.1.1.7.0.268435455.1")  # multi-byte arcs
    assert snmp._decode_oid(snmp._oid(big)[2:]) == big
    assert snmp._length(127) == b"\x7f" and snmp._length(128) == b"\x81\x80" and snmp._length(300) == b"\x82\x01\x2c"
    assert snmp._value(0x46, b"\x00\xff\xff\xff\xff\xff\xff\xff\xff") == 2**64 - 1
    assert snmp._value(0x40, bytes([10, 0, 0, 1])) == "10.0.0.1"
    assert snmp.text(b"core-sw1\x00") == "core-sw1" and snmp.text(b"\x02\x00\xff") == "02:00:ff"
    for junk in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x02\x01\x00", b"\x30\x03\x02\x01"):
        try:
            snmp.decode_message(junk)
        except snmp.SnmpError:
            continue
        raise AssertionError(f"accepted {junk!r}")


def test_parse_target():
    assert parse_target("10.0.0.1") == ("10.0.0.1", 161) and parse_target("10.0.0.1:1161") == ("10.0.0.1", 1161)
    for bad in ("switch.lan", "10.0.0.1:0", "10.0.0.1:x", "::1", ""):
        try:
            parse_target(bad)
        except ValueError:
            continue
        raise AssertionError(bad)


# --- client + poller against fake agents ----------------------------------------------
async def _poll_network(mibs, client, previous=None):
    agents = await snmp_sim.serve(mibs, first_port=0)
    try:
        return {name: await poll_device(client, "127.0.0.1", port, "public", (previous or {}).get(name))
                for name, (_, _, port) in agents.items()}, agents
    finally:
        for transport, _, _ in agents.values():
            transport.close()


def test_client_get_walk_and_timeout():
    async def go():
        client = snmp.SnmpClient(timeout=0.3, retries=1)
        agents = await snmp_sim.serve({"sw": snmp_sim.network()["core-sw1"]}, first_port=0)
        port = agents["sw"][2]
        try:
            got = await client.get("127.0.0.1", port, "public", [snmp.oid("1.3.6.1.2.1.1.5.0"), snmp.oid("1.3.6.1.9.9.0")])
            assert got[snmp.oid("1.3.6.1.2.1.1.5.0")] == b"core-sw1.lan" and got[snmp.oid("1.3.6.1.9.9.0")] is None
            names = await client.walk("127.0.0.1", port, "public", snmp.oid("1.3.6.1.2.1.31.1.1.1.1"))
            assert len(names) == 12 and names[0] == ((1,), b"GigabitEthernet1/0/1") and names[-1][0] == (12,)
            assert await client.walk("127.0.0.1", port, "public", snmp.oid("1.3.6.1.2.1.99")) == []
            try:
                await client.get("127.0.0.1", port, "wrong", [snmp.oid("1.3.6.1.2.1.1.5.0")])
            except snmp.SnmpTimeout:
                pass
            else:
                raise AssertionError("wrong community should time out")
            assert not client._pending
        finally:
            agents["sw"][0].close()
            client.close()
    asyncio.run(go())


def test_poll_and_topology():
    async def go():
        client = snmp.SnmpClient(timeout=1, retries=1)
        try:
            return (await _poll_network(snmp_sim.network(), client))[0]
        finally:
            client.close()
    data = asyncio.run(go())

    sw = data["core-sw1"]
    assert sw["system"]["name"] == "core-sw1.lan" and sw["system"]["uptime_seconds"] == 86400 * 12
    assert sw["chassis_id"] == snmp_sim.SW_MAC and sw["ips"] == ["192.168.1.4"]
    assert sw["interfaces"]["1"]["name"] == "GigabitEthernet1/0/1" and sw["interfaces"]["1"]["oper"] == "up"
    assert sw["interfaces"]["12"]["oper"] == "down" and sw["interfaces"]["2"]["in_octets"] == 18_000_000_000
    by_name = {n["sys_name"]: n for n in sw["neighbors"]}
    assert set(by_name) == {"OPNsense.lan", "PA-440", "FGT-60F", "rtl-sw2", "ap-lobby"}  # CDP duplicate dropped
    assert by_name["PA-440"]["local_port"] == "GigabitEthernet1/0/2" and by_name["PA-440"]["mgmt_ip"] == "192.168.1.2"
    assert by_name["PA-440"]["chassis_id"] == snmp_sim.PA_MAC and by_name["PA-440"]["port_id"] == "ethernet1/2"
    assert "Gi1/0/2" in by_name["PA-440"]["local_names"] and by_name["FGT-60F"]["proto"] == "lldp"

    # Log sources as the engine knows them: syslog source IPs differ from the SNMP management IPs.
    devices = [{"id": name, "ip": "127.0.0.1", "hostname": name, "name": "", "connector_seen": conn}
               for name, conn in (("OPNsense.lan", "opnsense"), ("PA-440", "paloalto"), ("FGT-60F", "fortinet"),
                                  ("core-sw1", "cisco_ios"), ("rtl-sw2", "rtl_playground"), ("nas", "generic"))]
    records = {name: {"ok": True, "polled": 1.0, "data": d} for name, d in data.items()}
    graph = build_topology(devices, records, {"core-sw1": {"high": 2, "low": 1}})
    nodes = {n["label"]: n for n in graph["nodes"]}
    assert set(nodes) == {"OPNsense.lan", "PA-440", "FGT-60F", "core-sw1.lan", "rtl-sw2", "nas", "ap-lobby"}
    assert nodes["ap-lobby"]["managed"] is False and nodes["ap-lobby"]["kind"] == "ap"
    assert nodes["rtl-sw2"]["managed"] and nodes["rtl-sw2"]["linked"] and nodes["rtl-sw2"]["snmp"] == "none"
    assert not nodes["nas"]["linked"] and nodes["core-sw1.lan"]["kind"] == "switch"
    assert (nodes["core-sw1.lan"]["alerts"], nodes["core-sw1.lan"]["severity"]) == (3, "high")
    # Five cables, each drawn once although three are reported from both ends.
    assert len(graph["links"]) == 5
    ends = {frozenset([(l["a"], l["a_port"]), (l["b"], l["b_port"])]) for l in graph["links"]}
    assert frozenset([("dev:core-sw1", "GigabitEthernet1/0/2"), ("dev:PA-440", "ethernet1/2")]) in ends
    assert frozenset([("dev:core-sw1", "GigabitEthernet1/0/3"), ("dev:FGT-60F", "internal1")]) in ends
    assert frozenset([("dev:core-sw1", "GigabitEthernet1/0/4"), ("dev:rtl-sw2", "1")]) in ends
    assert all(l["speed_mbps"] == 1000 and l["oper"] == "up" for l in graph["links"])


def test_rates_and_neighbor_changes():
    async def go():
        client = snmp.SnmpClient(timeout=1, retries=1)
        try:
            first, _ = await _poll_network({"core-sw1": snmp_sim.network()["core-sw1"]}, client)
            first["core-sw1"]["collected"] -= 100  # pretend the first poll was 100 s ago
            grown = dict(snmp_sim.network(with_rogue=True)["core-sw1"])
            key = snmp.oid("1.3.6.1.2.1.31.1.1.1.6.1")
            grown[key] = (snmp_sim.COUNTER64, grown[key][1] + 125_000_000)  # +1 Gbit over 100 s
            for column in range(4, 11):  # the access point is unplugged
                grown.pop(snmp.oid(f"1.0.8802.1.1.2.1.4.1.1.{column}.0.5.5"))
            second, _ = await _poll_network({"core-sw1": grown}, client, first)
            third, _ = await _poll_network({"core-sw1": grown}, client, second)
            return first["core-sw1"], second["core-sw1"], third["core-sw1"]
        finally:
            client.close()
    first, second, third = asyncio.run(go())
    assert "in_bps" not in first["interfaces"]["1"]
    assert 9_000_000 < second["interfaces"]["1"]["in_bps"] < 11_000_000
    new, lost = diff_neighbors(first, second)
    assert [n["sys_name"] for n in new] == ["netgear-gs108"] and lost == []
    assert list(second["pending_lost"]) == ["GigabitEthernet1/0/5|02:00:00:00:06:00"]
    new, lost = diff_neighbors(second, third)  # still missing on the next poll: now it counts
    assert new == [] and [n["sys_name"] for n in lost] == ["ap-lobby"] and third["pending_lost"] == {}
    assert diff_neighbors(third, third) == ([], [])


def test_norm_port():
    assert norm_port("GigabitEthernet1/0/1") == norm_port("Gi1/0/1") == "gi1/0/1"
    assert norm_port("TenGigabitEthernet 1/1/1") == "te1/1/1" and norm_port("igb0") == "igb0"
