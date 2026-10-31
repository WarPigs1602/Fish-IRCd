# Fish-IRCd installation

Fish-IRCd is an actively developed IRC server based on Undernet's ircu2.
This guide covers building and installing it from a source checkout.

## Build requirements

You need a C compiler, GNU make, Autoconf, Automake, Bison, Flex, pkg-config,
and development files for the TLS library you choose. On Debian or Ubuntu,
the following installs the build tools and OpenSSL development files:

```sh
sudo apt-get update
sudo apt-get install build-essential autoconf automake bison flex pkg-config libssl-dev
```

## Generate and build

From the repository root, generate the build system, configure, and compile:

```sh
./autogen.sh
./configure --prefix="$HOME" --with-tls=openssl
make
make check
```

The default installation prefix is your home directory. The TLS backend can
be selected with `--with-tls=none`, `--with-tls=openssl`,
`--with-tls=gnutls`, or `--with-tls=libtls`; install the matching development
package before configuring. To see other configuration options, run
`./configure --help`.

## Install and configure

Install the server and its sample configuration:

```sh
make install
```

With the commands above, the server is installed as `$HOME/bin/ircd`, and
the data directory is `$HOME/lib`. `make install` places the sample
configuration at `$HOME/lib/example.conf`. Copy it to the default
configuration filename and edit it for your server:

```sh
cp "$HOME/lib/example.conf" "$HOME/lib/ircd.conf"
${EDITOR:-vi} "$HOME/lib/ircd.conf"
```

Review the configuration before exposing the server to a network. Set the
server identity, network links, operator credentials, and TLS certificate
paths as appropriate; the sample configuration is not production-ready.
Check the configuration, then start the server in the foreground:

```sh
"$HOME/bin/ircd" -k -d "$HOME/lib" -f ircd.conf
"$HOME/bin/ircd" -n -d "$HOME/lib" -f ircd.conf
```

The first command checks the configuration and exits. The second runs the
server without detaching from the terminal. Omit `-n` to let it detach.

For a system-wide installation, choose an appropriate prefix (for example
`/usr/local`) when running `./configure`, and install with the permissions
required for that prefix. `--with-dpath=dir` can be used to set a different
server data directory. Additional configuration details are in
[`doc/example.conf`](doc/example.conf) and the documentation under
[`doc/`](doc/).
