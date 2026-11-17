"""Flag -> fix -> re-run tests for EventBridge event-routing checks (emulator)."""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck

RESOURCE = 'EventBridge::Account'


def _cleanupRule(ev, name):
    try:
        ids = [t['Id'] for t in ev.list_targets_by_rule(Rule=name).get('Targets', [])]
        if ids:
            ev.remove_targets(Rule=name, Ids=ids)
    except Exception:
        pass
    try:
        ev.delete_rule(Name=name)
    except Exception:
        pass


def _routingRule(emu, uid, name, pattern):
    """Return (misconfigure, fix, cleanup): misconfigure creates the rule with no
    target (does not count as routed); fix adds an SQS target."""
    ev = emu.client('events')
    sqs = emu.client('sqs')
    state = {}

    def misconfigure():
        ev.put_rule(Name=name, EventPattern=json.dumps(pattern), State='ENABLED')

    def fix():
        url = sqs.create_queue(QueueName=f'ss-eb-{uid}')['QueueUrl']
        state['url'] = url
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        ev.put_targets(Rule=name, Targets=[{'Id': 't1', 'Arn': arn}])

    def cleanup():
        _cleanupRule(ev, name)
        if state.get('url'):
            try:
                sqs.delete_queue(QueueUrl=state['url'])
            except Exception:
                pass

    return misconfigure, fix, cleanup


def test_eb_security_findings_not_routed(emu, uid):
    misconfigure, fix, cleanup = _routingRule(
        emu, uid, f'ss-sec-{uid}', {'source': ['aws.guardduty'], 'detail-type': ['GuardDuty Finding']})
    try:
        assertFlagFixCycle(emu, 'eventbridge', 'securityFindingsNotRouted', RESOURCE, misconfigure, fix)
    finally:
        cleanup()


def test_eb_security_findings_disabled_rule_not_counted(emu, uid):
    ev = emu.client('events')
    misconfigure, fix, cleanup = _routingRule(
        emu, uid, f'ss-sec2-{uid}', {'$or': [{'source': ['aws.inspector2']}, {'source': ['aws.securityhub']}]})
    try:
        misconfigure()
        fix()
        assert runCheck(emu, 'eventbridge', 'securityFindingsNotRouted', RESOURCE).flagged() == []
        ev.disable_rule(Name=f'ss-sec2-{uid}')
        assert runCheck(emu, 'eventbridge', 'securityFindingsNotRouted', RESOURCE).flagged() == [RESOURCE]
    finally:
        cleanup()


def test_eb_health_events_not_routed(emu, uid):
    misconfigure, fix, cleanup = _routingRule(emu, uid, f'ss-health-{uid}', {'source': ['aws.health']})
    try:
        assertFlagFixCycle(emu, 'eventbridge', 'healthEventsNotRouted', RESOURCE, misconfigure, fix)
    finally:
        cleanup()
