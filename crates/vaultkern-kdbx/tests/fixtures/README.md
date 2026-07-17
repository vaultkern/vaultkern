# KeePassXC KDBX 4.1 fixture

`keepassxc-2.7.6-kdbx4.1.kdbx` was written by the Debian KeePassXC 2.7.6
`keepassxc-cli` executable from the adjacent XML source on 2026-07-17:

```text
rtk keepassxc-cli import -q -p -t 100 \
  keepassxc-2.7.6-kdbx4.1-source.xml \
  keepassxc-2.7.6-kdbx4.1.kdbx
```

The group tag and entry `QualityCheck` value in the source require KDBX 4.1,
so KeePassXC selected header version `0x00040001`. The fixture password is
`vaultkern-external-fixture`; every credential in this directory is public
test data.

Pinned SHA-256 values:

```text
ef38f5908251aca9547e61d6ed45652c63703159637222f989c3e12afc334c62  keepassxc-2.7.6-kdbx4.1.kdbx
5df22d15a61bb89f810352d63c0c1efb7481d30f4a57428ac9c59590f2a84d57  keepassxc-2.7.6-kdbx4.1-source.xml
```

Do not regenerate the binary as part of a normal test run. A replacement is a
reviewed fixture update: record the generating KeePassXC version and command,
pin the new hashes, and verify the header and semantic sentinel before commit.
