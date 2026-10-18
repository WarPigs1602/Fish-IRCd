"""Channel mode +H and IRCv3 chathistory across servers."""

import pytest

from irc_client import IRCClient

from .helpers import join_synced


pytestmark = pytest.mark.multi_server


async def test_history_mode_and_cross_server_chathistory(ircd_network):
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    channel = "#histcompat"

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("histsender", "testuser", "Hist Sender")

    reader = IRCClient()
    await reader.connect(leaf["host"], leaf["port"])
    acked = await reader.negotiate_cap(
        ["batch", "server-time", "message-tags", "draft/chathistory"]
    )
    assert "draft/chathistory" in acked
    await reader.register("histreader", "testuser", "Hist Reader")

    try:
        await sender.send(f"JOIN {channel}")
        await sender.wait_for("JOIN")
        await join_synced(channel, sender, reader)

        # +H takes lines:duration with the duration in hours or days
        await sender.send(f"MODE {channel} +H 5:2d")
        mode = await reader.wait_for("MODE", timeout=5.0)
        assert mode.params[1:] == ["+H", "5:2d"], mode.raw

        await sender.send(f"MODE {channel} +H 5:x")
        await sender.send(f"MODE {channel} +H 6:12h")
        mode = await reader.wait_for("MODE", timeout=5.0)
        assert mode.params[1:] == ["+H", "6:12h"], mode.raw

        for i in range(8):
            await sender.send(f"PRIVMSG {channel} :history line {i}")
            await reader.wait_for("PRIVMSG", timeout=5.0)

        await reader.send(f"CHATHISTORY LATEST {channel} * 3")
        start = await reader.wait_for("BATCH", timeout=5.0)
        assert start.params[1:] == ["chathistory", channel], start.raw
        lines = []
        while True:
            msg = await reader.recv(timeout=5.0)
            if msg.command == "BATCH":
                assert msg.params[0] == "-" + start.params[0][1:], msg.raw
                break
            assert msg.command == "PRIVMSG", msg.raw
            assert "msgid=" in msg.tags and "time=" in msg.tags, msg.raw
            lines.append(msg.params[-1])
        assert lines == ["history line 5", "history line 6", "history line 7"]

        await sender.send(f"MODE {channel} -H")
        mode = await reader.wait_for("MODE", timeout=5.0)
        assert mode.params[1:] == ["-H"], mode.raw
    finally:
        await sender.disconnect()
        await reader.disconnect()
