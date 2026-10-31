# Installation de Fish-IRCd

Fish-IRCd est un serveur IRC en développement actif, basé sur ircu2
d'Undernet. Ce guide explique comment le compiler et l'installer depuis une
copie du dépôt source.

## Prérequis

Il vous faut un compilateur C, GNU make, Autoconf, Automake, Bison, Flex,
pkg-config ainsi que les fichiers de développement de la bibliothèque TLS
choisie. Sous Debian ou Ubuntu, les commandes suivantes installent les outils
de compilation et les fichiers de développement d'OpenSSL :

```sh
sudo apt-get update
sudo apt-get install build-essential autoconf automake bison flex pkg-config libssl-dev
```

## Génération et compilation

Depuis la racine du dépôt, générez le système de compilation, configurez le
projet et compilez-le :

```sh
./autogen.sh
./configure --prefix="$HOME" --with-tls=openssl
make
make check
```

Par défaut, le préfixe d'installation est votre répertoire personnel. Vous
pouvez choisir le backend TLS avec `--with-tls=none`,
`--with-tls=openssl`, `--with-tls=gnutls` ou `--with-tls=libtls` ; installez
les fichiers de développement correspondants avant de lancer la
configuration. Pour consulter les autres options, exécutez
`./configure --help`.

## Installation et configuration

Installez le serveur et son exemple de configuration :

```sh
make install
```

Avec les commandes ci-dessus, le serveur est installé dans `$HOME/bin/ircd`
et le répertoire de données est `$HOME/lib`. `make install` place l'exemple
de configuration dans `$HOME/lib/example.conf`. Copiez-le sous le nom de
fichier de configuration par défaut, puis modifiez-le pour votre serveur :

```sh
cp "$HOME/lib/example.conf" "$HOME/lib/ircd.conf"
${EDITOR:-vi} "$HOME/lib/ircd.conf"
```

Examinez attentivement la configuration avant d'exposer le serveur à un
réseau. Définissez notamment l'identité du serveur, les liens réseau, les
identifiants des opérateurs et les chemins des certificats TLS. L'exemple
n'est pas prêt pour une utilisation en production.

Vérifiez la configuration, puis démarrez le serveur au premier plan :

```sh
"$HOME/bin/ircd" -k -d "$HOME/lib" -f ircd.conf
"$HOME/bin/ircd" -n -d "$HOME/lib" -f ircd.conf
```

La première commande vérifie la configuration puis se termine. La seconde
exécute le serveur sans le détacher du terminal. Omettez `-n` pour laisser le
serveur se détacher.

Pour une installation système, choisissez un préfixe adapté (par exemple
`/usr/local`) lors de l'exécution de `./configure`, puis installez le serveur
avec les permissions requises pour ce préfixe. L'option
`--with-dpath=répertoire` permet de choisir un autre répertoire de données.
Pour plus de détails sur la configuration, consultez
[`doc/example.conf`](doc/example.conf) et la documentation du répertoire
[`doc/`](doc/).
