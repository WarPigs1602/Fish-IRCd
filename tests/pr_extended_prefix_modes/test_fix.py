"""Extended channel prefix modes are independent from +o."""

import pytest

from cap_helpers import burst_lines
from p10_server import P10Server

pytestmark = pytest.mark.single_server


async def test_extended_prefix_modes_do_not_add_or_remove_chanop(
    make_client, ircd_hub
):
    oper = await make_client("xpoper")
    chanop = await make_client("xpop")
    owner = await make_client("xpowner")
    admin = await make_client("xpadmin")
    halfop = await make_client("xphalfop")
    service = await make_client("xpservice")
    unprefixed = await make_client("xpunprefixed")
    channel = "#extended_prefix_modes"

    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)
    try:
        for feature in (
            "CHMODE_OWNER",
            "CHMODE_ADMIN",
            "CHMODE_HALFOP",
            "CHMODE_SERVICE",
        ):
            await oper.send(f"SET {feature} TRUE")
            await oper.wait_for("284", timeout=8.0)

        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        for client in (owner, admin, halfop, service):
            await client.send(f"JOIN {channel}")
            await client.wait_for("366")
            await chanop.wait_for("JOIN")

        # A server operator can seed the first owner; this then exercises the
        # regular MODE path for subsequent extended prefixes.
        await oper.send(f"OPMODE {channel} +q {chanop.nick}")
        await chanop.wait_for("MODE")
        await chanop.send(f"MODE {channel} +qa {owner.nick} {admin.nick}")
        changed = await chanop.wait_for("MODE")
        assert changed.params[1] == "+qa", changed.params

        # +y is restricted to services/servers, so exercise its normal server
        # mode path as well.
        await oper.send(f"OPMODE {channel} +y {service.nick}")
        await chanop.wait_for("MODE")
        await oper.send(f"OPMODE {channel} +h {halfop.nick}")
        await chanop.wait_for("MODE")

        await owner.send(f"MODE {channel} +m")
        owner_mode = await owner.wait_for("MODE")
        assert owner_mode.params[1] == "+m", owner_mode.params

        await chanop.send(f"MODE {channel} +o {owner.nick}")
        await chanop.wait_for("MODE")
        await chanop.send(f"MODE {channel} -o {owner.nick}")
        await chanop.wait_for("MODE")

        await chanop.send(f"NAMES {channel}")
        names = await chanop.collect_until("366")
        entries = [
            entry
            for message in names
            if message.command == "353"
            for entry in message.params[-1].split()
        ]
        for prefix, client in (
            ("~", owner),
            ("&", admin),
            ("%", halfop),
            ("!", service),
        ):
            entry = next(item for item in entries if item.endswith(client.nick))
            assert entry.startswith(prefix), f"{client.nick}: {entry!r}"
            assert "@" not in entry[: -len(client.nick)], entry
        chanop_entry = next(item for item in entries if item.endswith(chanop.nick))
        assert chanop_entry.startswith("~@"), chanop_entry

        for feature in (
            "CHMODE_OWNER",
            "CHMODE_ADMIN",
            "CHMODE_HALFOP",
            "CHMODE_SERVICE",
        ):
            await oper.send(f"SET {feature} FALSE")
            await oper.wait_for("284", timeout=8.0)

        await chanop.send(f"NAMES {channel}")
        names = await chanop.collect_until("366")
        entries = [
            entry
            for message in names
            if message.command == "353"
            for entry in message.params[-1].split()
        ]
        for client in (owner, admin, halfop, service):
            entry = next(item for item in entries if item.endswith(client.nick))
            prefix = entry[: -len(client.nick)]
            assert not any(char in prefix for char in "~&%!"), entry

        await unprefixed.send(f"JOIN {channel}")
        await unprefixed.wait_for("366")
        for mode in ("q", "a", "h", "y"):
            await oper.send(f"OPMODE {channel} +{mode} {unprefixed.nick}")
            await oper.wait_for("472", timeout=8.0)

        await chanop.send(f"NAMES {channel}")
        names = await chanop.collect_until("366")
        entries = [
            entry
            for message in names
            if message.command == "353"
            for entry in message.params[-1].split()
        ]
        unprefixed_entry = next(
            item for item in entries if item.endswith(unprefixed.nick)
        )
        assert not any(
            char in unprefixed_entry[: -len(unprefixed.nick)]
            for char in "~&%!"
        ), unprefixed_entry

        observer = P10Server(
            name="notulined.test.net",
            numeric=5,
            password="testpass",
        )
        await observer.connect(ircd_hub["host"], ircd_hub["server_port"])
        await observer.handshake()
        try:
            burst = next(
                line for line in burst_lines(observer, "B")
                if channel in line
            )
            for client, mode in (
                (owner, "q"),
                (admin, "a"),
                (halfop, "h"),
                (service, "y"),
            ):
                assert f"{client.nick}:{mode}" not in burst, burst
        finally:
            await observer.disconnect()

    finally:
        for feature in (
            "CHMODE_OWNER",
            "CHMODE_ADMIN",
            "CHMODE_HALFOP",
            "CHMODE_SERVICE",
        ):
            await oper.send(f"SET {feature} FALSE")
            await oper.wait_for("284", timeout=8.0)
