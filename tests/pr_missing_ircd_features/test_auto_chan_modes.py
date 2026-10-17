"""Regression tests for configured automatic channel modes."""

import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.multi_server


async def test_auto_channel_modes_reach_other_servers(ircd_network):
    """Modes set on a locally created channel are propagated after CREATE."""
    hub, leaf = ircd_network["hub"], ircd_network["leaf1"]
    creator = IRCClient()
    observer = IRCClient()
    channel = "#auto_modes_features"

    await creator.connect(hub["host"], hub["port"])
    await observer.connect(leaf["host"], leaf["port"])
    try:
        await creator.register("automodes", "testuser", "Auto Modes")
        user_modes = await creator.send_and_expect("MODE automodes", "221")
        assert "i" in user_modes.params[-1], (
            f"AUTOINVISIBLE did not set +i at registration: {user_modes.params[-1]!r}"
        )

        await creator.send(f"JOIN {channel}")
        await creator.wait_for("366")

        local_modes = await creator.chan_modes(channel)
        assert all(mode in local_modes for mode in "ntCN"), (
            f"local channel lacks configured default modes: {local_modes!r}"
        )

        await observer.register("modeobserver", "testuser", "Mode Observer")
        await observer.send(f"JOIN {channel}")
        await observer.wait_for("366")

        remote_modes = await observer.chan_modes(channel)
        assert all(mode in remote_modes for mode in "ntCN"), (
            f"channel modes were not propagated after CREATE: {remote_modes!r}"
        )
    finally:
        for client in (creator, observer):
            try:
                await client.send("QUIT :test cleanup")
            except Exception:
                pass
            await client.disconnect()
