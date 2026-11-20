#!/usr/bin/env python3
"""
Run a single Service Screener check (or one service's checks) without the full
scan bootstrap. Useful for developing and testing checks.

Examples
  # One check, real account (uses your normal AWS credentials / --profile)
  python3 run_check.py --service s3 --check PublicReadAccessBlock --region ap-southeast-1

  # Against the local AWS Emulator only (real credentials are removed from the process)
  python3 run_check.py --service s3 --check PublicReadAccessBlock --emulator

  # Assert the outcome (exit 1 if not met) - handy in scripts
  python3 run_check.py --service s3 --check PublicReadAccessBlock --emulator \
      --resource my-bucket --expect -1
"""
import argparse
import json
import os
import sys

# constants.ROOT_DIR is derived from the working directory.
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

import boto3  # noqa: E402
from utils.CheckRunner import CheckRunner, emulatorSession, resourceIdMatches  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--service', '-s', required=True, help='Service folder name, e.g. s3, iam, ec2')
    p.add_argument('--check', '-c', help='Result key (e.g. PublicReadAccessBlock) or method name without _check (e.g. Access)')
    p.add_argument('--region', '-r', default='us-east-1')
    p.add_argument('--resource', help='Only report this resource: its full identifier, its name '
                                      '(e.g. my-bucket for Bucket::my-bucket) or the last ARN segment')
    p.add_argument('--profile', '-p', help='AWS profile (ignored with --emulator)')
    p.add_argument('--emulator', nargs='?', const=9297, type=int, metavar='PORT',
                   help='Use the local AWS Emulator on 127.0.0.1:PORT (default 9297)')
    p.add_argument('--expect', type=int, choices=[-1, 0, 1],
                   help='Exit 1 unless every reported resource has this status')
    p.add_argument('--expect-not', type=int, choices=[-1, 0, 1], dest='expectNot',
                   help='Exit 1 if any reported resource has this status')
    p.add_argument('--json', action='store_true', help='Print full JSON results')
    p.add_argument('--debug', action='store_true')
    a = p.parse_args(argv)

    if a.emulator:
        session = emulatorSession(port=a.emulator, region=a.region)
    else:
        session = boto3.session.Session(profile_name=a.profile, region_name=a.region)

    res = CheckRunner.run(a.service, a.check, region=a.region, session=session,
                          resource=a.resource, emulator=bool(a.emulator), debug=a.debug)
    if a.resource:
        # CheckRunner filters by substring; keep only exact identifier matches
        # so 'bucket-1' does not also cover 'bucket-10'.
        res.results = {rid: v for rid, v in res.results.items() if resourceIdMatches(rid, a.resource)}

    if a.json:
        print(json.dumps(res.toDict(), indent=2, default=str))
    else:
        for rid, checks in res.results.items():
            for k, v in checks.items():
                print(f"{rid}\t{k}\t{v[0] if v else ''}\t{v[1] if len(v) > 1 else ''}")
        if res.errors:
            print(f"\n{len(res.errors)} check error(s); rerun with --json for details", file=sys.stderr)

    # Every key in res.results: the requested key, or all keys returned by
    # the method when --check is a method name (e.g. Access).
    statuses = {f'{rid} {k}': st for (rid, k), st in res.allStatuses().items()} if a.check else {}
    if a.expect is not None or a.expectNot is not None:
        if not statuses:
            print(f"EXPECTATION FAILED: no result for check '{a.check}'", file=sys.stderr)
            return 1
        if a.expect is not None and any(s != a.expect for s in statuses.values()):
            print(f"EXPECTATION FAILED: expected {a.expect}, got {statuses}", file=sys.stderr)
            return 1
        if a.expectNot is not None and any(s == a.expectNot for s in statuses.values()):
            print(f"EXPECTATION FAILED: did not expect {a.expectNot}, got {statuses}", file=sys.stderr)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
