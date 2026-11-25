# Ledger archive reader

This tool reads an Agave ledger and produces Compact V2 data. It opens the
ledger in read-only mode.

```text
hivezilla-ledger-archive check-ledger-range <LEDGER> --start-slot N --end-slot M
hivezilla-ledger-archive build-epoch-archive <LEDGER> <OUTPUT-PARENT> --epoch N
hivezilla-ledger-archive public-epoch-to-cf <OUTPUT-PARENT> --epoch N
hivezilla-ledger-archive read-slot-compact --ledger <LEDGER> --slot N
```

`public-epoch-to-cf` uploads every file in the epoch directory that
`EPOCH_ARCHIVE_FILES` names. The bucket, prefix, endpoint, and keys come from
`R2_BUCKET`, `R2_PREFIX`, `R2_ENDPOINT` or `R2_S3_ENDPOINT`, `R2_ACCESS_KEY_ID`,
and `R2_SECRET_ACCESS_KEY`. An object that already has the same size stays in
place. After the upload, one Telegram line is sent when `TELEGRAM_BOT_TOKEN`
and `TELEGRAM_CHAT_ID` are set. A Telegram failure still exits 0.

The default build fetches upstream Agave tag `v4.4.0-rc.1`, commit
`b6149a719f8fa84123ac3ce1e5f201af64bca8ee`. Cargo does not need a local
`agave-ledger` checkout. Its lock file is separate from the main workspace.
The default build supports the range and epoch commands.

`read-slot-compact` requires `bounded-ledger-read` and an Agave tree that
defines `BlockstoreOptions::read_only_max_open_files`. The upstream
`v4.4.0-rc.1` tag does not define that field. A default build rejects this
command before it opens the ledger.

The one-slot command writes a bounded `BZLGR01!` response with metadata and one
Compact V2 bundle to standard output. It requires a rooted, complete block and
all transaction status records. It writes no archive or notification. The
resolver checks the response identity and its configured ledger generation.
Ledger results have no native stream cursor or Bank identity.

The port preserves the RC1 dependency profile. It does not prove compatibility
with the final 4.4.0 validator profile. The bounded reader still needs a matching
host build and real-ledger checks for its time and memory limits before use.
