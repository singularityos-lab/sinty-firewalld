# sinty-firewalld

The firewall daemon of Sinty OS. It keeps one nftables table,
`inet singularity_firewall`, and lets the session open ports for an app over
D-Bus. The ruleset is written through netlink by `libsinty-system-core`; no
`nft` binary is needed.

## The ruleset

The `input` chain drops by default and accepts, in order: established and
related traffic, loopback, ICMP and ICMPv6, DHCP and DHCPv6 replies, mDNS on
home networks, then one rule per app. Each app rule carries the app's label as
its comment, so `nft list ruleset` shows who opened what. The whole table is
replaced in one batch: the kernel never holds half a ruleset.

On a public network only the apps allowed there too keep their ports, and mDNS
is closed. With the firewall off the table is removed.

## D-Bus

Name `dev.sinty.Firewall1`, object `/dev/sinty/Firewall1`, interface
`dev.sinty.Firewall1`.

| Member | Signature | |
| --- | --- | --- |
| `Status` | `() -> (b enabled, s profile, a(sbss) rules)` | a rule is id, public too, ports, label |
| `SetEnabled` | `(b)` | |
| `SetProfile` | `(s)` | `home` or `public` |
| `Allow` | `(s id, b public_too, s ports, s label)` | replaces the rule with the same id |
| `Revoke` | `(s id)` | |
| `Changed` | signal, same arguments as `Status` | |

Ports are `22/tcp`, `5353/udp` or `8000-8010/tcp`, comma separated, at most 16
per app and 64 apps. An id is 1 to 32 characters of `a-z`, `0-9` and `-`.
Root and regular users (uid 1000 and up) may change the firewall; system
accounts may only read it. Invalid input fails with
`dev.sinty.Firewall1.Error.Invalid`, a ruleset the kernel refuses with
`dev.sinty.Firewall1.Error.Failed`, and the previous ruleset stays in place.

The kernel needs `CONFIG_NF_TABLES`, `CONFIG_NF_TABLES_INET`, `CONFIG_NFT_CT`
and `CONFIG_NF_CONNTRACK`.

## Usage

    sinty-firewalld [-state /var/lib/sinty-firewalld/state.json]
    sinty-firewalld -show     # what the kernel holds now

## Build

    make build
    make release          # stripped binary for the image
    make test

Requires Go >= 1.25, cgo and `libsinty-system-core` (pkg-config
`sinty-system-1`) from libsingularity. The other dependency is
`github.com/godbus/dbus/v5`.
