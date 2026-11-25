# Native block stream client

Typed client for the retained Bank stream. It pins the complete native source,
producer generation and cursor, validates frames and controls, and reports
expired history explicitly. It does not discover a source, infer finality from
elapsed time, or replace missing frames with archive reconstructions.

Keep source, Bank and frame identity in stored checkpoints. Resume and commit
application effects together. Full protocol details are preserved in the
private integration references; public Rust types and errors are documented
with the code.
