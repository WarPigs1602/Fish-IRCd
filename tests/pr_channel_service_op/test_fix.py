"""Channel services receive the configured channel prefix."""

import asyncio

import pytest

from cap_helpers import burst_lines
from p10_server import P10Server

pytestmark = pytest.mark.single_server


async def test_channel_service_is_opped_and_cannot_be_deopped(
    make_client, ulined_server
):
    client = await make_client("svcopter")
    channel = "#svcopter"
    await client.send(f"JOIN {channel}")
    await client.wait_for("366")

    service = await ulined_server.introduce_user("ChanService", modes="+k")
    await ulined_server.send_join(service, channel)

    join = await client.wait_for("JOIN")
    assert join.prefix.startswith("ChanService!")

    mode = await client.wait_for("MODE")
    assert mode.params == [channel, "+o", "ChanService"]
    assert mode.prefix.startswith("*."), "+o must come from the network, not the nick"

    await client.send(f"MODE {channel} -o ChanService")
    error = await client.wait_for("484")
    assert "ChanService" in error.params

    await ulined_server._send(
        f"{ulined_server.server_numnick} M {channel} -o ChanService"
    )
    await asyncio.sleep(0.1)
    await client.send(f"NAMES {channel}")
    names = await client.wait_for("353")
    assert any("@ChanService" in param for param in names.params)


async def test_channel_service_gets_only_service_prefix_when_enabled(
    make_client, ulined_server
):
    oper = await make_client("svcfeatureop")
    client = await make_client("svcfeatureuser")
    channel = "#svcfeature"
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)

    try:
        await oper.send("SET CHMODE_SERVICE TRUE")
        await oper.wait_for("284", timeout=8.0)

        await client.send(f"JOIN {channel}")
        await client.wait_for("366")

        service = await ulined_server.introduce_user("ChanServiceY", modes="+k")
        await ulined_server.send_join(service, channel)
        await client.wait_for("JOIN")
        mode = await client.wait_for("MODE")
        assert mode.params == [channel, "+y", "ChanServiceY"]
        await client.send(f"NAMES {channel}")
        names = await client.collect_until("366")
        entries = [
            entry
            for message in names
            if message.command == "353"
            for entry in message.params[-1].split()
        ]
        service_entry = next(
            entry for entry in entries if entry.endswith("ChanServiceY")
        )
        assert service_entry.startswith("!"), service_entry
        assert "@" not in service_entry[: -len("ChanServiceY")], service_entry

        created_channel = "#svcfeaturecreate"
        creator = await ulined_server.introduce_user("ChanServiceCreator", modes="+k")
        await ulined_server.send_join(creator, created_channel)

        await client.send(f"JOIN {created_channel}")
        await client.wait_for("366")
        await client.send(f"NAMES {created_channel}")
        names = await client.collect_until("366")
        entries = [
            entry
            for message in names
            if message.command == "353"
            for entry in message.params[-1].split()
        ]
        service_entry = next(
            entry for entry in entries if entry.endswith("ChanServiceCreator")
        )
        assert service_entry.startswith("!"), service_entry
        assert "@" not in service_entry[: -len("ChanServiceCreator")], service_entry
    finally:
        await oper.send("SET CHMODE_SERVICE FALSE")
        await oper.wait_for("284", timeout=8.0)


async def test_channel_service_burst_uses_enabled_prefix_mode(
    make_client, ulined_server, ircd_hub
):
    oper = await make_client("svcburstoper")
    client = await make_client("svcburstuser")
    channel = "#svcburst"
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)

    observers = []
    try:
        await oper.send("SET CHMODE_SERVICE TRUE")
        await oper.wait_for("284", timeout=8.0)

        await client.send(f"JOIN {channel}")
        await client.wait_for("366")
        service = await ulined_server.introduce_user("ChanServiceBurst", modes="+k")
        await ulined_server.send_join(service, channel)
        await client.wait_for("JOIN")

        observer = P10Server(
            name="notulined.test.net",
            numeric=5,
            password="testpass",
        )
        observers.append(observer)
        await observer.connect(ircd_hub["host"], ircd_hub["server_port"])
        await observer.handshake()
        burst = next(
            line for line in burst_lines(observer, "B")
            if channel in line and "ChanServiceBurst:" in line
        )
        member_modes = next(
            token.split(":", 1)[1]
            for token in burst.replace(",", " ").split()
            if token.startswith("ChanServiceBurst:")
        )
        assert member_modes == "y", burst

        await oper.send("SET CHMODE_SERVICE FALSE")
        await oper.wait_for("284", timeout=8.0)
        fallback_observer = P10Server(
            name="uworldonly.test.net",
            numeric=6,
            password="testpass",
        )
        observers.append(fallback_observer)
        await fallback_observer.connect(ircd_hub["host"], ircd_hub["server_port"])
        await fallback_observer.handshake()
        burst = next(
            line for line in burst_lines(fallback_observer, "B")
            if channel in line and "ChanServiceBurst:" in line
        )
        member_modes = next(
            token.split(":", 1)[1]
            for token in burst.replace(",", " ").split()
            if token.startswith("ChanServiceBurst:")
        )
        assert member_modes == "o", burst
        await fallback_observer.disconnect()
    finally:
        for observer in observers:
            await observer.disconnect()
        await oper.send("SET CHMODE_SERVICE FALSE")
        await oper.wait_for("284", timeout=8.0)
