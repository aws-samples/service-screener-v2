import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.athena.drivers.AthenaWorkgroup import AthenaWorkgroup

KMS_KEY_ARN = 'arn:aws:kms:eu-central-1:111122223333:key/11111111-2222-3333-4444-555555555555'


def workgroup(configuration, name='wg-test'):
    """A workgroup record as Athena.py builds it: get_work_group's WorkGroup plus
    '_name', '_tags' and '_region'. Configuration shapes mirror real
    get_work_group responses."""
    return {
        'Name': name,
        'State': 'ENABLED',
        'Configuration': configuration,
        '_name': name,
        '_tags': [],
        '_region': 'eu-central-1',
    }


## Managed query results, encrypted with the default AWS owned key.
MANAGED_AWS_OWNED_KEY = {
    'ManagedQueryResultsConfiguration': {'Enabled': True},
    'EnforceWorkGroupConfiguration': True,
    'EnableMinimumEncryptionConfiguration': False,
}


## Managed query results, encrypted with a customer KMS key.
MANAGED_KMS_KEY = {
    'ManagedQueryResultsConfiguration': {
        'Enabled': True,
        'EncryptionConfiguration': {'KmsKey': KMS_KEY_ARN},
    },
    'EnforceWorkGroupConfiguration': True,
    'EnableMinimumEncryptionConfiguration': False,
}


## Customer results location, as on real workgroups: no
## ManagedQueryResultsConfiguration key at all.
CUSTOMER_LOCATION_SSE_S3 = {
    'ResultConfiguration': {
        'OutputLocation': 's3://example-results-bucket/athena/',
        'EncryptionConfiguration': {'EncryptionOption': 'SSE_S3'},
    },
    'EnforceWorkGroupConfiguration': True,
    'EnableMinimumEncryptionConfiguration': False,
}

CUSTOMER_LOCATION_UNENCRYPTED = {
    'ResultConfiguration': {'OutputLocation': 's3://example-results-bucket/athena/'},
    'EnforceWorkGroupConfiguration': False,
    'EnableMinimumEncryptionConfiguration': False,
}


class DriverTestCase(unittest.TestCase):
    def setUp(self):
        self.athenaClient = MagicMock()
        self.s3Client = MagicMock()

    def driver(self, configuration):
        return AthenaWorkgroup(workgroup(configuration), self.athenaClient, self.s3Client)


class TestAthenaWorkgroupManagedQueryResults(DriverTestCase):
    def test_encryption_passes_for_managed_query_results_with_aws_owned_key(self):
        d = self.driver(MANAGED_AWS_OWNED_KEY)
        d._checkAthenaWorkgroupNotEncrypted()
        status, message = d.results['athenaWorkgroupNotEncrypted']
        self.assertEqual(status, 1)
        self.assertIn('managed query results', message)
        self.assertIn('AWS owned key', message)

    def test_encryption_passes_for_managed_query_results_with_kms_key(self):
        d = self.driver(MANAGED_KMS_KEY)
        d._checkAthenaWorkgroupNotEncrypted()
        status, message = d.results['athenaWorkgroupNotEncrypted']
        self.assertEqual(status, 1)
        self.assertIn('managed query results', message)
        self.assertIn(KMS_KEY_ARN, message)

    def test_minimum_encryption_not_applicable_for_managed_query_results(self):
        d = self.driver(MANAGED_AWS_OWNED_KEY)
        d._checkAthenaMinimumEncryptionDisabled()
        status, message = d.results['athenaMinimumEncryptionDisabled']
        self.assertEqual(status, 0)
        self.assertIn('managed query results', message)
        self.assertNotIn('no encryption configured', message)

    def test_output_prefix_not_applicable_for_managed_query_results(self):
        d = self.driver(MANAGED_AWS_OWNED_KEY)
        d._checkAthenaWorkgroupS3OutputNoPrefix()
        status, message = d.results['athenaWorkgroupS3OutputNoPrefix']
        self.assertEqual(status, 0)
        self.assertIn('managed query results', message)

    def test_output_bucket_not_applicable_for_managed_query_results(self):
        d = self.driver(MANAGED_AWS_OWNED_KEY)
        d._checkAthenaS3OutputNotEncrypted()
        status, message = d.results['athenaS3OutputNotEncrypted']
        self.assertEqual(status, 0)
        self.assertIn('managed query results', message)
        self.s3Client.get_bucket_encryption.assert_not_called()

    def test_info_fields_show_managed_query_results_with_aws_owned_key(self):
        d = self.driver(MANAGED_AWS_OWNED_KEY)
        self.assertEqual(d.InventoryInfo['managedQueryResults'], 'True')
        self.assertEqual(d.InventoryInfo['encryptionOption'], 'AWS_OWNED_KEY')

    def test_info_fields_show_customer_kms_key_for_managed_query_results(self):
        d = self.driver(MANAGED_KMS_KEY)
        self.assertEqual(d.InventoryInfo['encryptionOption'], 'CUSTOMER_KMS_KEY')
        self.assertNotIn(KMS_KEY_ARN, ' '.join(str(v) for v in d.InventoryInfo.values()))

    def test_encryption_configuration_without_kms_key_means_aws_owned_key(self):
        d = self.driver({'ManagedQueryResultsConfiguration': {
            'Enabled': True, 'EncryptionConfiguration': {}}})
        d._checkAthenaWorkgroupNotEncrypted()
        self.assertEqual(d.results['athenaWorkgroupNotEncrypted'][0], 1)
        self.assertIn('AWS owned key', d.results['athenaWorkgroupNotEncrypted'][1])
        self.assertEqual(d.InventoryInfo['encryptionOption'], 'AWS_OWNED_KEY')

    def test_managed_query_results_disabled_is_a_customer_results_location(self):
        d = self.driver({'ManagedQueryResultsConfiguration': {'Enabled': False}})
        d._checkAthenaWorkgroupNotEncrypted()
        self.assertEqual(d.results['athenaWorkgroupNotEncrypted'][0], -1)
        self.assertEqual(d.InventoryInfo['managedQueryResults'], 'False')


class TestAthenaWorkgroupCustomerResultsLocation(DriverTestCase):
    """Workgroups without managed query results keep their existing behaviour."""

    def test_encryption_fails_without_encryption_configuration(self):
        d = self.driver(CUSTOMER_LOCATION_UNENCRYPTED)
        d._checkAthenaWorkgroupNotEncrypted()
        self.assertEqual(d.results['athenaWorkgroupNotEncrypted'][0], -1)

    def test_encryption_passes_with_sse_s3(self):
        d = self.driver(CUSTOMER_LOCATION_SSE_S3)
        d._checkAthenaWorkgroupNotEncrypted()
        status, message = d.results['athenaWorkgroupNotEncrypted']
        self.assertEqual(status, 1)
        self.assertIn('SSE_S3', message)

    def test_minimum_encryption_fails_when_disabled(self):
        d = self.driver(CUSTOMER_LOCATION_SSE_S3)
        d._checkAthenaMinimumEncryptionDisabled()
        self.assertEqual(d.results['athenaMinimumEncryptionDisabled'][0], -1)

    def test_output_bucket_encryption_is_read_from_s3(self):
        self.s3Client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}
        d = self.driver(CUSTOMER_LOCATION_SSE_S3)
        d._checkAthenaS3OutputNotEncrypted()
        self.assertEqual(d.results['athenaS3OutputNotEncrypted'][0], 1)
        self.s3Client.get_bucket_encryption.assert_called_once_with(
            Bucket='example-results-bucket')

    def test_info_fields_show_customer_results_location(self):
        d = self.driver(CUSTOMER_LOCATION_SSE_S3)
        self.assertEqual(d.InventoryInfo['managedQueryResults'], 'False')
        self.assertEqual(d.InventoryInfo['encryptionOption'], 'SSE_S3')


if __name__ == '__main__':
    unittest.main()
