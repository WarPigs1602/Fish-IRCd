"""Channel services must receive and retain channel operator status."""

import asyncio

import pytest

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
