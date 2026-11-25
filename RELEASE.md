# Release process

A software release version and a block wire-format version describe different
contracts. A Blockzilla 1.x release can support Compact V2. Experimental Compact
V3 work does not, by itself, make the software version 3.x.

## Version policy

Use `vMAJOR.MINOR.PATCH` tags and [Semantic Versioning](https://semver.org/) for
the documented public APIs and CLI behavior:

- Patch: a compatible correction.
- Minor: a compatible feature.
- Major: an incompatible public contract change.

Use a tag such as `v1.0.0-rc.1` for a release candidate. State its known limits
and the supported format versions. Do not replace a published tag or artifact;
publish a new version for a correction.

## Prepare a release

1. Select and record the exact commit. Review the changes since the last release.
2. Update version fields for the packages being released and check their
   dependency versions and lockfiles.
3. Run the [contribution checks](CONTRIBUTING.md#local-checks) and all relevant
   component checks. Confirm CI passes for the selected commit.
4. Run the fixed [sample-block benchmark](bench/sample-block/README.md). Record
   its input identity and correctness result. Label timings with the machine
   and command; keep full result sets in the private records repository.
5. For a validator-facing change, complete the selected Agave profile checks
   and the matched host/plugin load test in the
   [compatibility guide](zillastream/agave-compatibility/README.md).
6. Prepare release notes with public behavior changes, supported formats,
   compatibility limits, known issues and upgrade steps. Attach build artifacts
   with checksums and the source revision where artifacts are provided.
7. A maintainer reviews the release candidate before a stable tag is published.

## First stable release

The 1.0 release still requires the complete live-plus-archive token-dump
acceptance check. It must preserve the shared finalized boundary, reconcile
overlap, and commit output with both checkpoints. Restart must not lose or
duplicate accepted rows. Gaps and expired native history must remain explicit.
The current archive-only example does not establish this result.

The selected Agave/Linux and RocksDB profile checks and the actual matched
host/plugin load must also pass before the first stable release. A green core
CI run alone does not prove these deployment contracts.

## Experiments and history

Keep experimental format code on a clearly marked V3 branch based on the clean
core. Keep private design notes, operational records and full benchmark results
in the private records repository. Do not merge old monorepo history back into
a cleaned public branch.

A history reset or branch deletion is separate from a normal release. It needs
a verified private backup, a tested restore and a reviewed list of affected
refs. Preserve license notices and attribution. Do not use a release task as
permission to rewrite existing history.
