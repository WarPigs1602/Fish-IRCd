"""Native server-to-server SASL account exchange and malformed replies."""

import asyncio
import time

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.single_server


@pytest.fixture
async def services(ircd_hub):
    """Connect a fake P10 services server to the hub and enable SASL."""
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    # Enable SASL through netconf, pointing at ourselves.
    await srv.send_config("sasl.server", "services.test.net")
    await srv.send_config("sasl.mechanisms", "PLAIN")
    await asyncio.sleep(0.5)
    yield srv
    await srv.disconnect()


async def _start_sasl(client, services):
    """Negotiate the sasl cap and send AUTHENTICATE PLAIN.

    Returns the opaque home-server target and host sent to services.
    """
    await client.send("CAP LS 302")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert "sasl" in msg.params[-1], "hub does not advertise sasl"

    await client.send("CAP REQ :sasl")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert msg.params[1] == "ACK", f"expected CAP ACK, got {msg.params}"

    await client.send("AUTHENTICATE PLAIN")

    # Hub sends: "<hubnum> AUTHENTICATE <home.cookie> <host> PLAIN"
    line = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
    parts = line.split()
    assert parts[4] == "PLAIN"
    assert parts[2].startswith(parts[0] + ".")
    return parts[2], parts[3]


async def _finish_registration(client, nick):
    """Complete registration after SASL and wait for the 001 welcome."""
    await client.send(f"NICK {nick}")
    await client.send(f"USER testuser 0 * :Test User")
    await client.send("CAP END")
    await client.wait_for("001", timeout=10.0)


async def test_sasl_ok_with_valid_account(ircd_hub, services):
    """Positive control: OK with a full account payload logs the client in."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        target, host = await _start_sasl(client, services)
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} S goodacct 42 1"
        )

        msg = await client.wait_for("903", timeout=5.0)
        assert msg is not None

        # A delayed final SCRAM acknowledgement must not turn success into 907.
        await client.send("AUTHENTICATE +")
        await client.assert_no_message("907", timeout=0.5)

        await _finish_registration(client, "iavok1")

        # The account must be attached: WHOIS shows 330 (RPL_WHOISACCOUNT).
        await client.send("WHOIS iavok1")
        found_account = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            msg = await client.recv(timeout=5.0)
            if msg.command == "330":
                found_account = msg.params[2]
            if msg.command == "318":  # end of WHOIS
                break
        assert found_account == "goodacct"
    finally:
        await client.disconnect()


@pytest.mark.parametrize("bad_reply", ["S", "S :::: 42 1", "S goodacct 42"])
async def test_sasl_ok_without_account_must_not_crash(
    ircd_hub, services, bad_reply
):
    """A success reply with a malformed account must not kill the ircd.

    A malformed success must not authenticate the user or crash the server.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        target, host = await _start_sasl(client, services)
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} {bad_reply}"
        )

        # Whatever the server decides about the reply, it must stay up:
        # the client must still be able to finish registering...
        await _finish_registration(client, "iavbad1")
    finally:
        await client.disconnect()

    # ...and brand-new connections must still be accepted.
    probe = IRCClient()
    await probe.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await probe.register("iavprobe", "testuser", "Test User")
    finally:
        await probe.send("QUIT :done")
        await probe.disconnect()


async def test_sasl_abort_ignores_late_success(ircd_hub, services):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        target, host = await _start_sasl(client, services)
        await client.send("AUTHENTICATE *")
        await client.wait_for("906", timeout=5.0)
        abort = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        assert abort.split()[2:] == [target, host, "*"]

        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} S stale 42 1"
        )
        await _finish_registration(client, "iavabort")
        await client.send("WHOIS iavabort")
        while True:
            msg = await client.recv(timeout=5.0)
            assert msg.command != "330"
            if msg.command == "318":
                break
    finally:
        await client.disconnect()


async def test_sasl_challenge_and_retry_after_failure(ircd_hub, services):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        target, host = await _start_sasl(client, services)
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} +"
        )
        challenge = await client.wait_for("AUTHENTICATE", timeout=5.0)
        assert challenge.params[-1] == "+"

        await client.send("AUTHENTICATE dGVzdA==")
        response = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        assert response.split()[2:] == [target, host, "dGVzdA=="]
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} F"
        )
        await client.wait_for("904", timeout=5.0)

        await client.send("AUTHENTICATE PLAIN")
        retry = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        assert retry.split()[2] != target
    finally:
        await client.disconnect()


async def test_sasl_success_after_registration(ircd_hub, services):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        target, host = await _start_sasl(client, services)
        await _finish_registration(client, "iavregistered")
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} S registered 42 1"
        )
        await client.wait_for("900", timeout=5.0)
        await client.wait_for("903", timeout=5.0)
        await client.send("WHOIS iavregistered")
        while True:
            msg = await client.recv(timeout=5.0)
            if msg.command == "330":
                assert msg.params[2] == "registered"
                break
            assert msg.command != "318", "account was not applied"
    finally:
        await client.disconnect()


async def test_registered_client_uses_snircd_nick_target(ircd_hub, services):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.register("iavnative", "testuser", "Test User")
        await client.send("CAP REQ :sasl")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK"

        await client.send("AUTHENTICATE PLAIN")
        request = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        parts = request.split()
        assert parts[2] == "iavnative"
        assert parts[4] == "PLAIN"

        await services._send(
            f"{services.server_numnick} AUTHENTICATE iavnative {parts[3]} S nativeacct 42 1"
        )
        await client.wait_for("900", timeout=5.0)
        await client.wait_for("903", timeout=5.0)
        await client.send("WHOIS iavnative")
        while True:
            msg = await client.recv(timeout=5.0)
            if msg.command == "330":
                assert msg.params[2] == "nativeacct"
                break
            assert msg.command != "318", "account was not applied"
    finally:
        await client.disconnect()


async def test_nick_before_registration_uses_native_target(ircd_hub, services):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :sasl")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK"
        await client.send("NICK iavprereg")
        await client.send("AUTHENTICATE PLAIN")

        request = await services.wait_for_token("AUTHENTICATE", timeout=5.0)
        parts = request.split()
        assert parts[2] == "iavprereg"
        await services._send(
            f"{services.server_numnick} AUTHENTICATE iavprereg {parts[3]} S prereg 42 1"
        )
        await client.wait_for("903", timeout=5.0)
        await client.send("USER testuser 0 * :Test User")
        await client.send("CAP END")
        await client.wait_for("001", timeout=10.0)
    finally:
        await client.disconnect()


async def test_sasl_rejects_other_server(ircd_hub, services):
    impostor = P10Server(name="notulined.test.net", numeric=5, password="testpass")
    await impostor.connect(ircd_hub["host"], ircd_hub["server_port"])
    await impostor.handshake()
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        target, host = await _start_sasl(client, services)
        await impostor._send(
            f"{impostor.server_numnick} AUTHENTICATE {target} {host} S impostor 42 1"
        )
        await services._send(
            f"{services.server_numnick} AUTHENTICATE {target} {host} S genuine 42 1"
        )
        await client.wait_for("903", timeout=5.0)
        await _finish_registration(client, "iavsource")
        await client.send("WHOIS iavsource")
        while True:
            msg = await client.recv(timeout=5.0)
            if msg.command == "330":
                assert msg.params[2] == "genuine"
                break
            assert msg.command != "318", "account was not applied"
    finally:
        await client.disconnect()
        await impostor.disconnect()


async def test_sasl_server_feature_fallback(ircd_hub, services):
    oper = IRCClient()
    await oper.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await oper.register("iavfeature", "testuser", "Test User")
        await oper.send("OPER testoper operpass")
        await oper.wait_for("381", timeout=5.0)
        await oper.send("SET SASL_SERVER services.test.net")
        await oper.wait_for("284", timeout=5.0)

        # Network configuration wins while it exists.
        await services.send_config("sasl.server", "missing.test.net")
        await asyncio.sleep(0.2)
        probe = IRCClient()
        await probe.connect(ircd_hub["host"], ircd_hub["port"])
        try:
            await probe.send("CAP LS 302")
            caps = await probe.wait_for("CAP", timeout=5.0)
            assert all(cap.split("=")[0] != "sasl" for cap in caps.params[-1].split())
        finally:
            await probe.disconnect()

        # Deleting the override restores the local snircd feature.
        await services.send_config("sasl.server", "")
        await asyncio.sleep(0.2)
        client = IRCClient()
        await client.connect(ircd_hub["host"], ircd_hub["port"])
        try:
            target, host = await _start_sasl(client, services)
            await services._send(
                f"{services.server_numnick} AUTHENTICATE {target} {host} F"
            )
            await client.wait_for("904", timeout=5.0)
        finally:
            await client.disconnect()
    finally:
        await oper.send("RESET SASL_SERVER")
        await oper.wait_for("284", timeout=5.0)
        await oper.disconnect()


async def test_sasl_capability_advertises_mechanisms(ircd_hub, services):
    """The sasl capability advertises the configured mechanism list."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        caps = msg.params[-1].split()
        assert "sasl=PLAIN" in caps, f"expected sasl=PLAIN in {caps}"
    finally:
        await client.disconnect()


async def test_sasl_mechanism_change_notifies_cap_notify(ircd_hub, services):
    """Changing sasl.mechanisms re-notifies registered cap-notify clients."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("NICK mechnotify")
        await client.send("USER testuser 0 * :Test User")
        await client.send("CAP END")
        await client.wait_for("001", timeout=10.0)

        await services.send_config("sasl.mechanisms", "PLAIN,EXTERNAL")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NEW", f"expected CAP NEW, got {msg}"
        assert msg.params[-1] == "sasl=PLAIN,EXTERNAL", f"got {msg}"
    finally:
        await services.send_config("sasl.mechanisms", "PLAIN")
        await client.disconnect()
