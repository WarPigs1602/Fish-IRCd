"""KNOCK requests for invite-only channels."""

import asyncio

import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.multi_server


async def test_knock_reaches_channel_operators_across_servers(ircd_network):
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    channel = "#knocktest"

    operator = IRCClient()
    await operator.connect(hub["host"], hub["port"])
    await operator.register("knockop", "testuser", "Knock Operator")

    requester = IRCClient()
    await requester.connect(leaf["host"], leaf["port"])
    await requester.register("knockuser", "testuser", "Knock User")

    try:
        await operator.send(f"JOIN {channel}")
        await operator.wait_for("366")
        await operator.send(f"MODE {channel} +i")
        await operator.wait_for("MODE")
        await asyncio.sleep(0.3)

        await requester.send(f"KNOCK {channel} :please let me in")
        confirm = await requester.wait_for("NOTICE")
        assert confirm.params[-1] == f"Knocked on {channel}", confirm.raw

        notice = await operator.wait_for("NOTICE", timeout=5.0)
        assert notice.params[-1].startswith("[Knock] by knockuser!"), notice.raw
        assert notice.params[-1].endswith("(please let me in)"), notice.raw

        await operator.send(f"MODE {channel} -i")
        await operator.wait_for("MODE")
        await asyncio.sleep(0.3)
        await requester.send(f"KNOCK {channel}")
        opened = await requester.wait_for("480")
        assert opened.params[-1] == "Channel is not invite only!"

        await operator.send(f"MODE {channel} +i")
        await operator.wait_for("MODE")
        await operator.send(f"INVITE knockuser {channel}")
        await operator.wait_for("341")
        await requester.send(f"JOIN {channel}")
        await requester.wait_for("366")
        await requester.send(f"KNOCK {channel}")
        already_joined = await requester.wait_for("480")
        assert already_joined.params[-1] == "You're already there!"
    finally:
        for client in (operator, requester):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
