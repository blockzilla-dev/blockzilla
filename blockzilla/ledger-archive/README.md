# Ledger archive reader

This tool reads an Agave ledger and produces Compact V2 data. It opens the
ledger in read-only mode.

```text
hivezilla-ledger-archive check-ledger-range <LEDGER> --start-slot N --end-slot M
hivezilla-ledger-archive build-epoch-archive <LEDGER> <OUTPUT-PARENT> --epoch N
hivezilla-ledger-archive read-slot-compact --ledger <LEDGER> --slot N
```

The build uses the separate sibling `agave-ledger` profile, based on the exact
upstream Agave `v4.4.0-rc.1` commit
`b6149a719f8fa84123ac3ce1e5f201af64bca8ee`, with the bounded read-only patch.
Its lock file is separate from the
main workspace. The default build supports the range and epoch commands.

`read-slot-compact` requires `bounded-ledger-read` and the matching external
Agave RC1 profile. That profile supplies the checked read-only open-file limit.
The patch and build preparation recipe belong in the separate Agave repository;
this repository does not contain patch copies. A default build rejects this
command before it opens the ledger.

The one-slot command writes a bounded `BZLGR01!` response with metadata and one
Compact V2 bundle to standard output. It requires a rooted, complete block and
all transaction status records. It writes no archive or notification. The
resolver checks the response identity and its configured ledger generation.
Ledger results have no native stream cursor or Bank identity.

The port preserves the RC1 dependency profile. It does not prove compatibility
with the final 4.4.0 validator profile. The bounded reader still needs a matching
host build and real-ledger checks for its time and memory limits before use.
