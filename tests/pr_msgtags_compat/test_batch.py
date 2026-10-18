"""IRCv3 batch capability and server-to-client batch delivery."""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server

from .helpers import join_synced


pytestmark = pytest.mark.multi_server


@pytest.fixture
async def services(ircd_network):
    hub = ircd_network["hub"]
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
        server_flags="s",
    )
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


async def test_batch_cap_and_batch_tag_delivery(ircd_network, services):
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    channel = "#batchcompat"

    batch_client = IRCClient()
    await batch_client.connect(leaf["host"], leaf["port"])
    acked = await batch_client.negotiate_cap(["batch"])
    assert "batch" in acked
    await batch_client.register("batchuser", "testuser", "Batch User")

    plain_client = IRCClient()
    await plain_client.connect(hub["host"], hub["port"])
    await plain_client.register("plainbatch", "testuser", "Plain Batch")

    try:
        down_num = await services.send_downstream_server("down.batch.test", 91)
        remote_nick = "BatchRemote"
        remote_numnick = await services.send_downstream_nick(
            down_num, remote_nick, server_numeric=91,
        )
        await services.send_downstream_join(remote_nick, channel)
        await join_synced(channel, batch_client, plain_client)

        await services._send(
            f"{down_num} BATCH +evt netsplit hub.test down.batch.test"
        )
        start = await batch_client.wait_for("BATCH", timeout=5.0)
        assert start.params[0:2] == ["+evt", "netsplit"], start.raw
        with pytest.raises(asyncio.TimeoutError):
            await plain_client.wait_for("BATCH", timeout=0.3)

        await services._send(
            f"@batch=evt {remote_numnick} P {channel} :batched event"
        )
        batch_msg = await batch_client.wait_for("PRIVMSG", timeout=5.0)
        plain_msg = await plain_client.wait_for("PRIVMSG", timeout=5.0)
        assert batch_msg.tags == "batch=evt", batch_msg.raw
        assert "batch" not in plain_msg.tags, plain_msg.raw

        await services._send(f"{down_num} BATCH -evt")
        end = await batch_client.wait_for("BATCH", timeout=5.0)
        assert end.params[0] == "-evt", end.raw
    finally:
        for client in (batch_client, plain_client):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
