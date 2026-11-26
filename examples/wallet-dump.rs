fn main() -> anyhow::Result<()> {
    blockzilla::archive_dump::run(blockzilla::archive_dump::Kind::Wallet)
}
