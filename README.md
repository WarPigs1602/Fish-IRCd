# Fish-IRCd

```text
      ><(((('>      F I S H - I R C D
```

Fish-IRCd is an actively developed IRC server based on [Undernet's ircu2](https://github.com/UndernetIRC/ircu2). It incorporates selected changes from [snircd](https://codeberg.org/quakenet/snircd) and aims to improve compatibility with snircd while retaining ircu2's P10 server protocol.

This repository is a development snapshot, not a ready-to-run public IRC network configuration. Review and adapt the sample configuration, network links, TLS certificates, and operator credentials before deploying a server.

## Project highlights

- P10 server-to-server protocol and ircu2-derived configuration.
- TLS support through OpenSSL, GnuTLS, or libtls.
- IPv4/IPv6 networking, SASL, WebSocket listeners, and IRCv3 features including BATCH and CHATHISTORY.
- Autotools-based build, with C unit tests and a Python/Docker integration test suite.

The current source identifies as `Fish-IRCd(1.0-SNAPSHOT)` and is based on ircu2 u2.10.12.19, with snircd 1.3.5 compatibility noted in its version string. See [`include/patchlevel.h`](include/patchlevel.h) for the version definition and [`ChangeLog.11`](ChangeLog.11), [`ChangeLog.12`](ChangeLog.12), and [`RELEASE.NOTES`](RELEASE.NOTES) for upstream history.

## Classic installation

On Debian or Ubuntu, install the build tools and a TLS development library:

```sh
sudo apt-get update
sudo apt-get install build-essential autoconf automake bison flex pkg-config libssl-dev
```

From the repository root, generate the build system, configure, compile, run the C test suite, and install under your home directory:

```sh
./autogen.sh
./configure --prefix="$HOME" --with-tls=openssl
make
make check
make install
```

`--with-tls` accepts `none`, `openssl`, `gnutls`, or `libtls`; install the matching development package before configuring. To see the other configure options, run `./configure --help`.

The default data directory with this prefix is `$HOME/lib`. Copy the example configuration there and edit it for your server:

```sh
cp "$HOME/lib/example.conf" "$HOME/lib/ircd.conf"
${EDITOR:-vi} "$HOME/lib/ircd.conf"
```

Review the configuration carefully before exposing the server to a network. In particular, set the server identity, network links, operator credentials, and TLS certificate paths; the example is not a production-ready configuration. Check the configuration and then start the server in the foreground:

```sh
"$HOME/bin/ircd" -k -d "$HOME/lib" -f ircd.conf
"$HOME/bin/ircd" -n -d "$HOME/lib" -f ircd.conf
```

Omit `-n` to let the server detach from the terminal. For a system-wide installation, choose an appropriate prefix (for example `/usr/local`) and install with the permissions required for that prefix. For further installation and configuration details, see [`INSTALL.md`](INSTALL.md), the [German installation guide](INSTALL_DE.md), the [French installation guide](INSTALL_FR.md), and [`doc/example.conf`](doc/example.conf).

## Running the integration tests

The Python integration tests use Docker Compose to start disposable IRC server topologies. Install Docker with its Compose plugin, Python 3.10 or newer, and [uv](https://docs.astral.sh/uv/), then run:

```sh
cd tests
uv sync
uv run pytest
```

To run tests that do not need Docker:

```sh
uv run pytest test_irc_client.py
```

The suite also supports pytest markers such as `single_server`, `multi_server`, `tls`, `tls_single`, `dns`, `limits`, and `nf_compat`. See [`tests/README.md`](tests/README.md) for test selection, Docker topologies, TLS setup, and details on the test harness.

## Documentation

- [`INSTALL.md`](INSTALL.md) — build and installation notes.
- [`INSTALL_DE.md`](INSTALL_DE.md) — Installationsanleitung auf Deutsch.
- [`INSTALL_FR.md`](INSTALL_FR.md) — guide d'installation en français.
- [`doc/example.conf`](doc/example.conf) — sample server configuration.
- [`doc/`](doc/) — protocol, configuration, and platform documentation.
- [`tests/README.md`](tests/README.md) — integration test guide.

## License

Fish-IRCd is distributed under the GNU General Public License, version 1 or (at your option) any later version. See [`LICENSE`](LICENSE).
