# ACM Simulation Scripts

Scripts to create and clean up AWS Certificate Manager (ACM) resources for
validating the 13 ACM checks implemented in `services/acm/`.

## What the scripts do

`create_test_resources.sh` creates:

| # | Certificate                       | Checks it exercises                                              |
|---|-----------------------------------|------------------------------------------------------------------|
| 1 | `*.wildcard.<test-domain>`        | `acmWildcardCert`                                                |
| 2 | `ct-disabled.<test-domain>` with `CertificateTransparencyLoggingPreference=DISABLED` | `acmCertTransparencyDisabled` (once ISSUED), `acmCertPendingValidation` (after 72h) |
| 3 | `untagged.<test-domain>` (created **without** tags) | `acmCertNoTags`                                                  |
| 4 | `pending.<test-domain>`           | `acmCertPendingValidation` (after 72h)                           |
| 5 | Imported self-signed, 60-day validity | `acmImportedCertNoAutoRenewal`, `acmCertExpiry90Days`            |
| 6 | Imported self-signed, backdated (expired 5 days ago) — best-effort | `acmCertExpired`                                                 |
| 7 | Imported RSA-1024 — best-effort   | `acmRSAKeyLength`                                                |

All certificates 1, 2, 4, 5, 6, 7 are tagged `ServiceScreenerTest=acm-test-<timestamp>`.
Certificate 3 is intentionally untagged; its ARN is recorded in `.acm-untagged-arn`
so the cleanup script can still find it.

## Checks that cannot be simulated cheaply

| Check                        | Why                                                                                        |
|------------------------------|--------------------------------------------------------------------------------------------|
| `acmCertExpiry30Days`        | Requires a cert with 1–30 days of validity remaining. Import a cert with `-days 20`.       |
| `acmCertRenewalFailed`       | Requires a real managed-renewal attempt to fail (DNS/CAA misconfig).                       |
| `acmCertRevoked`             | Only revocable via AWS Private CA.                                                         |
| `acmCertNotInUse`            | Cert must be `ISSUED`. Public ACM certs need real DNS validation records first.            |
| `acmCertRenewalIneligible`   | Requires an ACM-issued cert on **email** validation (not usable in most test domains).     |
| `acmRSAKeyLength`            | ACM increasingly rejects RSA-1024 imports. Script attempts and reports.                    |

## Prerequisites

- AWS CLI configured, targeting an account you own.
- Local OpenSSL (for imports).
- IAM permissions: `acm:RequestCertificate`, `acm:ImportCertificate`,
  `acm:ListCertificates`, `acm:ListTagsForCertificate`,
  `acm:AddTagsToCertificate`, `acm:DeleteCertificate`.

## Usage

Create resources:

```bash
cd services/acm/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh
```

Set `AWS_REGION` to target a different region (default `ap-southeast-1`):

```bash
AWS_REGION=us-east-1 ./create_test_resources.sh
```

The script prints a tag value like `acm-test-20260702-152500`. Keep it — you
need it for cleanup.

Run Service Screener against just the ACM checks:

```bash
cd ../../../   # back to project root
python3 main.py --regions ap-southeast-1 --services acm --beta 1 --sequential 1
```

Clean up when done:

```bash
cd services/acm/simulation
./cleanup_test_resources.sh acm-test-20260702-152500
```

## Cost

- ACM public certificates: **free**.
- Imported certificates: free.
- The only charges come from calling APIs (negligible) and, if you attach a
  cert to an ALB/CloudFront distribution, from that resource — this script
  never attaches certificates to anything.

## Cleanup notes

- Certificates in `PENDING_VALIDATION` can be deleted immediately.
- Certificates that are `ISSUED` and attached to a resource cannot be deleted
  until the attachment is removed. The cleanup script reports failures per-ARN.
- Deletion is irreversible; the script does not confirm interactively so it
  can run in CI.

## Troubleshooting

- **`openssl` refuses RSA-1024** on modern macOS: the system OpenSSL enforces
  minimum key strength. Install and use the Homebrew OpenSSL or accept that
  the `acmRSAKeyLength` check will not be exercised locally.
- **`ImportCertificate` rejects the RSA-1024 or expired cert**: some regions
  enforce ACM-side validation. The script logs a warning and continues.
- **Certificates still show up after cleanup**: run
  `aws acm list-certificates --region <region> --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1`
  and delete manually with `aws acm delete-certificate --certificate-arn <arn>`.
