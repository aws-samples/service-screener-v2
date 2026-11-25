"""Flag -> fix -> re-run tests for resiliencehub checks against the local AWS Emulator.

Emulated here:
- resilienceHubAssessmentStale: an app that was never assessed is flagged; running an
  assessment (it reaches Success in the emulator) clears it. The "older than 30 days"
  branch needs an old endTime the emulator cannot produce - see tests/test_stub_resiliencehub.py.
- resilienceHubNoPolicy: an app without a resiliency policy is flagged; attaching one
  clears it. (list_resiliency_policies is NotImplemented in the emulator; the check only
  uses it for the informational policy count, so the verdict path is still exercised.)

resilienceHubDriftOrBreach is Stubber-only: the emulator always reports PolicyMet /
NotChecked, so a breach or drift cannot be produced.
"""
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck

POLICY = {k: {'rpoInSecs': 3600, 'rtoInSecs': 3600} for k in ('Software', 'Hardware', 'AZ')}


def _assessableApp(emu, uid, **kwargs):
    """Create an app with one real SQS queue and a published release version."""
    rh, sqs = emu.client('resiliencehub'), emu.client('sqs')
    qurl = sqs.create_queue(QueueName=f'ss-rh-{uid}')['QueueUrl']
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
    arn = rh.create_app(name=f'ss-rh-{uid}', **kwargs)['app']['appArn']
    rh.create_app_version_app_component(appArn=arn, name='queues', type='AWS::ResilienceHub::QueueAppComponent')
    rh.create_app_version_resource(appArn=arn, appComponents=['queues'], logicalResourceId={'identifier': 'queue1'},
                                   physicalResourceId=qarn, resourceType='AWS::SQS::Queue', resourceName='queue1')
    rh.publish_app_version(appArn=arn)
    return arn, qurl


def _cleanup(emu, arn, qurl, policyArn=None):
    rh, sqs = emu.client('resiliencehub'), emu.client('sqs')
    for fn in (lambda: arn and rh.delete_app(appArn=arn, forceDelete=True),
               lambda: qurl and sqs.delete_queue(QueueUrl=qurl),
               lambda: policyArn and rh.delete_resiliency_policy(policyArn=policyArn)):
        try:
            fn()
        except Exception:
            pass


def test_resiliencehub_assessment_stale(emu, uid):
    rh = emu.client('resiliencehub')
    arn = qurl = None
    try:
        arn, qurl = _assessableApp(emu, uid)

        def misconfigure():
            pass  # freshly created app: never assessed

        def fix():
            rh.start_app_assessment(appArn=arn, appVersion='release', assessmentName=f'ss-{uid}')
            for _ in range(30):
                rows = rh.list_app_assessments(appArn=arn)['assessmentSummaries']
                if rows and rows[0]['assessmentStatus'] == 'Success':
                    return
                time.sleep(1)
            raise AssertionError('assessment did not reach Success in the emulator')

        assertFlagFixCycle(emu, 'resiliencehub', 'resilienceHubAssessmentStale', f'App::ss-rh-{uid}', misconfigure, fix)
    finally:
        _cleanup(emu, arn, qurl)


def test_resiliencehub_no_policy(emu, uid):
    rh = emu.client('resiliencehub')
    arn = qurl = policyArn = None
    try:
        arn, qurl = _assessableApp(emu, uid)
        policyArn = rh.create_resiliency_policy(policyName=f'ss-rh-{uid}', tier='Critical',
                                                policy=POLICY)['policy']['policyArn']

        def misconfigure():
            pass  # app created without policyArn

        def fix():
            rh.update_app(appArn=arn, policyArn=policyArn)

        before, after = assertFlagFixCycle(emu, 'resiliencehub', 'resilienceHubNoPolicy', 'ResilienceHub::Account',
                                           misconfigure, fix)
        res = runCheck(emu, 'resiliencehub', 'resilienceHubNoPolicy', 'ResilienceHub::Account')
        assert list(res.statuses().values()) == [1], res.results
    finally:
        _cleanup(emu, arn, qurl, policyArn)


def test_resiliencehub_drift_pass_path(emu, uid):
    """Only the non-finding path is emulatable: an assessed app with a policy is PolicyMet."""
    rh = emu.client('resiliencehub')
    arn = qurl = policyArn = None
    try:
        policyArn = rh.create_resiliency_policy(policyName=f'ss-rh-{uid}', tier='Critical',
                                                policy=POLICY)['policy']['policyArn']
        arn, qurl = _assessableApp(emu, uid, policyArn=policyArn)
        before = runCheck(emu, 'resiliencehub', 'resilienceHubDriftOrBreach', f'App::ss-rh-{uid}').statuses()
        assert list(before.values()) == [0], before  # NotAssessed -> not evaluable, never PASS
        rh.start_app_assessment(appArn=arn, appVersion='release', assessmentName=f'ss-{uid}')
        for _ in range(30):
            if rh.describe_app(appArn=arn)['app'].get('complianceStatus') == 'PolicyMet':
                break
            time.sleep(1)
        after = runCheck(emu, 'resiliencehub', 'resilienceHubDriftOrBreach', f'App::ss-rh-{uid}').statuses()
        assert list(after.values()) == [1], after
    finally:
        _cleanup(emu, arn, qurl, policyArn)
