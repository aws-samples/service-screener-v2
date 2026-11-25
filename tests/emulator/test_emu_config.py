"""Flag -> fix -> re-run tests for the AWS Config account-level rule checks.

AWS Config rules require a configuration recorder, so each test makes sure one
exists (creating a throwaway recorder only if the account has none, and
deleting it again afterwards). The checks are account/region scoped and report
under the 'Config::Account' identifier, so the resource filter is 'Account'.

The tests need an account with no pre-existing Config rules (a fresh emulator):
any existing rule could already satisfy a check, so they skip otherwise.
"""
import contextlib

import pytest

from tests.emulator.conftest import assertFlagFixCycle

RESOURCE = 'Account'


@contextlib.contextmanager
def _cleanConfigAccount(emu, uid):
    cfg = emu.client('config')
    if cfg.describe_config_rules().get('ConfigRules'):
        pytest.skip('account already has AWS Config rules; needs a clean emulator')
    created = None
    if not cfg.describe_configuration_recorders().get('ConfigurationRecorders'):
        acct = emu.client('sts').get_caller_identity()['Account']
        created = 'default'
        cfg.put_configuration_recorder(ConfigurationRecorder={
            'name': created,
            'roleARN': f'arn:aws:iam::{acct}:role/ss-test-config-{uid}',
            'recordingGroup': {'allSupported': True, 'includeGlobalResourceTypes': True},
        })
    rules = []
    try:
        yield cfg, rules
    finally:
        for name in rules:
            try:
                cfg.delete_remediation_configuration(ConfigRuleName=name)
            except Exception:
                pass
            try:
                cfg.delete_config_rule(ConfigRuleName=name)
            except Exception:
                pass
        if created:
            try:
                cfg.delete_configuration_recorder(ConfigurationRecorderName=created)
            except Exception:
                pass


def _putRule(cfg, rules, name, identifier, modes=None):
    rule = {'ConfigRuleName': name,
            'Source': {'Owner': 'AWS', 'SourceIdentifier': identifier}}
    if modes:
        rule['EvaluationModes'] = [{'Mode': m} for m in modes]
    cfg.put_config_rule(ConfigRule=rule)
    if name not in rules:
        rules.append(name)


def test_config_no_proactive_rules(emu, uid):
    with _cleanConfigAccount(emu, uid) as (cfg, rules):
        name = f'ss-test-pro-{uid}'

        def misconfigure():
            ## No EvaluationModes -> DETECTIVE only (the default).
            _putRule(cfg, rules, name, 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED')

        def fix():
            _putRule(cfg, rules, name, 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED',
                     modes=['DETECTIVE', 'PROACTIVE'])

        assertFlagFixCycle(emu, 'config', 'configNoProactiveRules', RESOURCE, misconfigure, fix)


def test_config_data_protection_rules_missing(emu, uid):
    with _cleanConfigAccount(emu, uid) as (cfg, rules):
        def misconfigure():
            ## Versioning is a resilience control, not a data-protection one.
            _putRule(cfg, rules, f'ss-test-ver-{uid}', 'S3_BUCKET_VERSIONING_ENABLED')

        def fix():
            _putRule(cfg, rules, f'ss-test-sse-{uid}', 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED')

        assertFlagFixCycle(emu, 'config', 'configDataProtectionRulesMissing', RESOURCE,
                           misconfigure, fix)


def test_config_remediation_manual_only(emu, uid):
    with _cleanConfigAccount(emu, uid) as (cfg, rules):
        name = f'ss-test-rem-{uid}'
        acct = emu.client('sts').get_caller_identity()['Account']
        base = {'ConfigRuleName': name, 'TargetType': 'SSM_DOCUMENT',
                'TargetId': 'AWS-ConfigureS3BucketVersioning'}

        def misconfigure():
            _putRule(cfg, rules, name, 'S3_BUCKET_VERSIONING_ENABLED')
            resp = cfg.put_remediation_configurations(
                RemediationConfigurations=[dict(base, Automatic=False)])
            assert not resp.get('FailedBatches'), resp

        def fix():
            resp = cfg.put_remediation_configurations(RemediationConfigurations=[dict(
                base, Automatic=True, MaximumAutomaticAttempts=3, RetryAttemptSeconds=60,
                Parameters={
                    'AutomationAssumeRole': {'StaticValue': {'Values': [
                        f'arn:aws:iam::{acct}:role/ss-test-remediation-{uid}']}},
                    'BucketName': {'ResourceValue': {'Value': 'RESOURCE_ID'}},
                })])
            assert not resp.get('FailedBatches'), resp

        assertFlagFixCycle(emu, 'config', 'configRemediationManualOnly', RESOURCE,
                           misconfigure, fix)
