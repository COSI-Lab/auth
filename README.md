# COSI auth

We officially admit defeat against SSSD, OpenLDAP, GSS-API, FreeIPA, Heimdal, MIT krb5, and all their ilk.

We maintain that the basics of the Linux auth stack are simple enough to target directly.

Here is how you can log into lab machines and manage your credentials.

## Architecture

auth is a centralized solution. `authd` runs an RPC service with the interface described in [authd/src/rpc.rs].

Endpoints configure `nss_cosiauthd` to communicate to the `authd`, which enables user/group database sharing over the network.

The `auth` tool allows for inspection and editing of the database, user password changes, etc.

The OPAQUE password-authenticated key exchange is used instead of password hashes.

## Local deployments for testing

!! WIP !! WIP !! WIP !! WIP !! WIP !!

All software will search for its config files first in `/etc/auth` and then in `$HOME/.config/auth`.
Generate a TLS certificate and key. I have only tested EC, not RSA. There's a keypair here for your
convenience, made with rcgen.

Write `/etc/auth/nss_cosiauthd.toml`, as an example:

```toml
host = '127.0.0.1:8765'
cert = '/etc/auth/cert.der'
```

Using the home directory is a bad idea for deployment, it is included in the authd example toml to
demonstrate that the paths in the authd config support basic shell expansion (env and tilde).

`sudo cp -r target/release/libnss_cosiauthd.so /lib/x86_64-linux-gnu/libnss_cosiauthd.so.2` will
make NSS know what is happening.

`getent -s cosiauthd passwd` should then hang in your terminal.

`cargo run --release --bin authd` in another terminal will start up a localhost server, and `getent`
should print its result (probably empty).

## ...

See each subproject for more specific documentation.