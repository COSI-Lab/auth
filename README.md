# COSI auth

We officially declare defeat against SSSD, OpenLDAP, GSS-API, FreeIPA, Heimdal, MIT krb5, and all their ilk.

We maintain that the basics of the Linux auth stack are simple enough to target directly.

Here is how you can log into lab machines and manage your credentials.

## Architecture

auth is a centralized solution. `authd` runs an RPC service with the interface described in [authd/src/rpc.rs].

Endpoints configure `nss_cosiauthd` to communicate to the `authd`, which enables user/group database sharing over the network.

The `auth` tool allows for inspection and editing of the database, user password changes, etc.

The OPAQUE password-authenticated key exchange is used instead of password hashes.

## Deploying

!! WIP !! WIP !! WIP !! WIP !! WIP !!

this software is currently too shitty to be deployable. FIXME: port+uri configuration.

`sudo cp -r target/release/libnss_cosiauthd.so /lib/x86_64-linux-gnu/libnss_cosiauthd.so.2` will make NSS know what is happening.

`getent -s cosiauthd passwd` should then hang in your terminal.

`cargo run --bin authd` in another terminal will start up a localhost server, and `getent` should print its result (probably empty).

## ...

See each subproject for more specific documentation.