# Project instructions

- Use ASD-STE100 Simplified Technical English with the user.
- Read `README.md`, `CONTRIBUTING.md`, and `RELEASE.md` before changing scope or release behavior.
- Keep implemented and tested behavior separate from planned features.
- Preserve exact format bytes, source identity, cursors, and fork controls.
- Read `zillastream/agave-compatibility/README.md` before changing validator integration.
- Keep deployment credentials, private infrastructure records, and research logs out of this repository.

- Implement native tools and process-test helpers in Rust.
- Do not add Python files or Python interpreter calls.
- Keep SSH adapters, key provisioning, deployment probes, operator notifications,
  and full benchmark tools in private infrastructure repositories. Keep public
  runtime APIs, self-contained tests, and the fixed sample benchmark here.
