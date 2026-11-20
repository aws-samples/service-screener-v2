"""wafv2 reporter references: each link label must describe its target page.
URLs and page titles were verified on 2026-11-20:
- web-acl-processing.html: "Using protection packs (web ACLs) with rules and rule groups in AWS WAF"
- APIReference/API_TagResource.html: "TagResource - AWS WAFV2" (there is no WAF developer-guide tagging page)
- owasp.org/Top10/2021/A03_2021-Injection/: "A03 Injection - OWASP Top 10:2021"
  (owasp.org/Top10/A03_2021-Injection/ only redirects to the top10.owasp.org host)."""
import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPORTER = json.load(open(os.path.join(ROOT, 'services', 'wafv2', 'wafv2.reporter.json')))
REF_RE = re.compile(r'^\[(?P<label>[^\]]+)\]<(?P<url>https?://[^>]+)>$')


def _refs(key):
    return {m.group('url'): m.group('label') for m in (REF_RE.match(r) for r in REPORTER[key]['ref']) if m}


def test_all_refs_are_label_url_pairs():
    for key, entry in REPORTER.items():
        for r in entry.get('ref') or []:
            assert REF_RE.match(r), (key, r)


def test_no_rules_processing_link_not_labelled_best_practices():
    refs = _refs('wafv2NoRules')
    url = 'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-processing.html'
    assert 'best practices' not in refs[url].lower()
    assert 'rule groups' in refs[url].lower()


def test_tag_resource_api_link_labelled_as_api_reference():
    for key, entry in REPORTER.items():
        for url, label in _refs(key).items():
            if url.endswith('/API_TagResource.html'):
                assert 'TagResource API' in label, (key, label)


def test_owasp_injection_link_uses_canonical_owasp_url():
    urls = [u for k in REPORTER for u in _refs(k) if 'owasp' in u]
    assert urls, 'expected the OWASP A03 reference'
    for u in urls:
        assert u.startswith('https://owasp.org/Top10/2021/'), u


# Page titles verified 2026-11-20 (docs.aws.amazon.com <title>). Every reference
# to one of these pages must carry a label that names the page topic.
EXPECTED_LABEL_WORDS = {
    'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-group-override-options.html': 'overriding',
    'https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html': 'rule action',
    'https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html': 'cloudwatch',
    'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-processing-order.html': 'priorit',
    'https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups-versioning.html': 'version',
}


def test_labels_match_target_page_topic():
    for key in REPORTER:
        for url, label in _refs(key).items():
            words = EXPECTED_LABEL_WORDS.get(url)
            if words:
                assert words in label.lower(), (key, label, url)


def test_override_reference_points_at_override_page():
    for key in REPORTER:
        for url, label in _refs(key).items():
            if label.lower().startswith('overriding'):
                assert url.endswith('/web-acl-rule-group-override-options.html'), (key, label, url)
