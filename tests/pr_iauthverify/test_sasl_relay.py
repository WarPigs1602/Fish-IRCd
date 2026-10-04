"""SASL availability and native AUTHENTICATE across server links."""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server, server_numeric


pytestmark = pytest.mark.multi_server


async def test_sasl_service_behind_hub_without_mechanism_list(ircd_network):
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    services = P10Server(name="services.test.net", numeric=4, password="testpass")
    await services.connect(hub["host"], hub["server_port"])
    await services.handshake()
    client = IRCClient()
    try:
        await services.send_config("sasl.server", services.name)
        await client.connect(leaf["host"], leaf["port"])

        for _ in range(25):
            await client.send("CAP LS 302")
            caps = await client.wait_for("CAP", timeout=5.0)
            if "sasl" in caps.params[-1].split():
                break
            await asyncio.sleep(0.2)
        else:
            pytest.fail("Leaf did not recognize the remote SASL service")

        await client.send("CAP REQ :sasl")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK"
        await client.send("AUTHENTICATE PLAIN")

        request = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        parts = request.split()
        assert parts[0] == server_numeric(2), "relay lost the leaf server prefix"
        assert parts[2].startswith(parts[0] + ".")
        assert parts[4] == "PLAIN"
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {parts[2]} {parts[3]} F"
        )
        await client.wait_for("904", timeout=5.0)

        # A remote failure must leave the client eligible for another attempt.
        await client.send("AUTHENTICATE PLAIN")
        retry = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        retry_parts = retry.split()
        assert retry_parts[2] != parts[2]
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {retry_parts[2]} "
            f"{retry_parts[3]} S relayacct 42 1"
        )
        await client.wait_for("903", timeout=5.0)
        await client.send("AUTHENTICATE +")
        await client.assert_no_message("907", timeout=0.5)
        await client.send("NICK relayuser")
        await client.send("USER testuser 0 * :Relay Test")
        await client.send("CAP END")
        await client.wait_for("001", timeout=10.0)
        await client.send("WHOIS relayuser")
        while True:
            msg = await client.recv(timeout=5.0)
            if msg.command == "330":
                assert msg.params[2] == "relayacct"
                break
            assert msg.command != "318", "remote SASL account was not applied"

        # 907 is reserved for an actual completed login, not a pending retry.
        await client.send("AUTHENTICATE PLAIN")
        await client.wait_for("907", timeout=5.0)
    finally:
        await client.disconnect()
        await services.disconnect()
