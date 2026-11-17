# Check tests against the local AWS Emulator

Every new check gets a **flag -> fix -> re-run** test: misconfigure a resource, assert the check
returns `-1`, apply the fix, re-run, assert it no longer returns `-1`. These tests run against the
[AWS Emulator](https://docs.aws.amazon.com/emulator/latest/userguide/what-is-service.html) on
`127.0.0.1`, so they need no AWS account and never touch real resources.

## Run

```bash
docker build --build-arg ARCH=$(uname -m | sed 's/arm64/aarch64/') -t aws-emulator tests/emulator
mkdir -p ~/.aws/emulator
docker run --rm --memory=2g -p 127.0.0.1:9297:9297 -e HOME="$HOME" \
  -v "$HOME/.aws/emulator:$HOME/.aws/emulator" aws-emulator -p 9297 --idle-timeout 7200
# (Finch works the same: replace docker with finch)

python -m pytest tests/emulator -q
```

Tests are skipped when the emulator is not running. Publish the port on `127.0.0.1` only.

## Safety

`utils/CheckRunner.emulatorSession()` removes real-credential environment variables from the
process, uses the emulator's own credentials, and `assertEmulatorOnly()` fails closed unless every
client points at `https://127.0.0.1:<port>`.

## Writing a test

See `test_emu_s3_template.py`. Use `assertFlagFixCycle(emu, service, checkKey, resourceName,
misconfigure, fix)` and a unique resource name from the `uid` fixture; clean up in `finally`.

## Account-wide checks

Checks whose result covers every resource in the account (for example "every data store is
tagged") must use the `emu_fresh` fixture instead of `emu`. It starts an empty emulator on a free
loopback port for that test, so resources left by other tests cannot change the outcome. It needs
`docker` or `finch` and the `aws-emulator` image (override with `SS_EMULATOR_IMAGE`).

## Known emulator limits

- One account and one Region; IAM policies are not evaluated (checks only read configuration).
- Not implemented (use mocked flag/fix tests instead): `organizations.list_delegated_administrators`,
  `backup.list_protected_resources`, `security-ir.list_memberships`.
- S3 Control (account-ID host prefix) cannot reach an IP endpoint; test those checks with mocks.
- The emulated Well-Architected lens is the 2025-02-25 version.

## Single-check runner

```bash
python3 run_check.py --service s3 --check PublicReadAccessBlock --emulator --resource my-bucket --expect -1
```
