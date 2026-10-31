# Fish-IRCd installieren

Fish-IRCd ist ein aktiv entwickelter IRC-Server auf Basis von Undernets
ircu2. Diese Anleitung beschreibt das Kompilieren und Installieren aus einem
Source-Checkout.

## Voraussetzungen

Benötigt werden ein C-Compiler, GNU make, Autoconf, Automake, Bison, Flex,
pkg-config sowie die Entwicklungsdateien der gewünschten TLS-Bibliothek.
Unter Debian oder Ubuntu installieren die folgenden Befehle die
Build-Werkzeuge und die OpenSSL-Entwicklungsdateien:

```sh
sudo apt-get update
sudo apt-get install build-essential autoconf automake bison flex pkg-config libssl-dev
```

## Build-System erzeugen und kompilieren

Führen Sie im Stammverzeichnis des Repositorys die folgenden Schritte aus,
um das Build-System zu erzeugen, das Projekt zu konfigurieren und zu
kompilieren:

```sh
./autogen.sh
./configure --prefix="$HOME" --with-tls=openssl
make
make check
```

Das Installationspräfix ist standardmäßig Ihr Home-Verzeichnis. Das
TLS-Backend lässt sich mit `--with-tls=none`, `--with-tls=openssl`,
`--with-tls=gnutls` oder `--with-tls=libtls` auswählen. Installieren Sie vor
der Konfiguration die passenden Entwicklungsdateien. Weitere
Konfigurationsoptionen finden Sie mit `./configure --help`.

## Installieren und konfigurieren

Installieren Sie den Server und die Beispielkonfiguration:

```sh
make install
```

Mit den obigen Befehlen wird der Server unter `$HOME/bin/ircd` installiert;
das Datenverzeichnis ist `$HOME/lib`. `make install` legt die
Beispielkonfiguration unter `$HOME/lib/example.conf` ab. Kopieren Sie sie
unter den Namen der Standardkonfigurationsdatei und passen Sie sie an:

```sh
cp "$HOME/lib/example.conf" "$HOME/lib/ircd.conf"
${EDITOR:-vi} "$HOME/lib/ircd.conf"
```

Prüfen Sie die Konfiguration sorgfältig, bevor Sie den Server für ein
Netzwerk erreichbar machen. Legen Sie insbesondere die Serveridentität,
Netzwerkverbindungen, Operator-Zugangsdaten und Pfade zu TLS-Zertifikaten
fest. Die Beispielkonfiguration ist nicht für den produktiven Einsatz
vorgesehen.

Prüfen Sie die Konfiguration und starten Sie den Server anschließend im
Vordergrund:

```sh
"$HOME/bin/ircd" -k -d "$HOME/lib" -f ircd.conf
"$HOME/bin/ircd" -n -d "$HOME/lib" -f ircd.conf
```

Der erste Befehl prüft die Konfiguration und beendet sich danach. Der zweite
startet den Server, ohne ihn vom Terminal zu lösen. Lassen Sie `-n` weg,
damit sich der Server vom Terminal löst.

Für eine systemweite Installation wählen Sie bei `./configure` ein passendes
Präfix (zum Beispiel `/usr/local`) und installieren Sie den Server mit den
für dieses Präfix erforderlichen Berechtigungen. Mit `--with-dpath=dir` lässt
sich ein anderes Server-Datenverzeichnis festlegen. Weitere Hinweise zur
Konfiguration finden Sie in [`doc/example.conf`](doc/example.conf) und in
der Dokumentation unter [`doc/`](doc/).
