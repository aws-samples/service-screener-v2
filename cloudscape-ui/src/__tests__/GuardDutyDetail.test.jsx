import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { HashRouter } from 'react-router-dom';

import GuardDutyDetail from '../components/GuardDutyDetail';

const PROMPT_INJECTION = {
  '^description': '2 GuardDuty detector(s) cannot generate PromptInjection.Direct findings',
  shortDesc: 'Enforce a Bedrock Guardrail prompt attack filter',
  criticality: 'M',
  __categoryMain: 'S',
  downtime: 0,
  slowness: -1,
  additionalCost: 1,
  needFullTest: 1,
  remediation: null,
  remediation_doc: 'https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html',
  __links: JSON.stringify(["<a href='https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html'>GuardDuty AI Protection</a>"]),
  __affectedResources: { 'us-east-1': ['Detector::abc123'] }
};

const AI_STATUS = {
  criticality: 'L',
  shortDesc: 'AI Protection status',
  __categoryMain: 'T',
  value: {
    AiProtectionDisabled: [1, 'AI Protection is enabled'],
    AiProtectionNoEventChannel: [1, 'GuardDuty channel streams Bedrock data events'],
    AiProtectionPromptInjectionNotDetected: [-1, 'No guardrail with an active prompt attack filter']
  }
};

const REPORT = {
  guardduty: {
    summary: {
      AiProtectionPromptInjectionNotDetected: PROMPT_INJECTION,
      RuntimeMonitoringDisabled: {
        shortDesc: 'Enable GuardDuty Runtime Monitoring',
        criticality: 'H',
        __categoryMain: 'S',
        downtime: 0,
        slowness: 0,
        additionalCost: 1,
        needFullTest: 0,
        __affectedResources: { 'us-east-1': ['Detector::abc123'] }
      },
      Settings: { shortDesc: 'Settings', criticality: 'L', __categoryMain: 'T' },
      AiProtectionStatus: AI_STATUS
    },
    detail: {
      'us-east-1': {
        'Detector::abc123': {
          AiProtectionStatus: AI_STATUS,
          AiProtectionPromptInjectionNotDetected: PROMPT_INJECTION
        }
      }
    }
  }
};

const draw = (data) => render(<HashRouter><GuardDutyDetail data={data} /></HashRouter>);

describe('GuardDutyDetail', () => {
  it('shows AI Protection coverage, including passing checks', () => {
    const text = draw(REPORT).container.textContent;

    expect(text).toContain('AI Protection finding type coverage');
    expect(text).toContain('Bedrock data events streamed (AnomalousModelInvocation, CostHarvesting)');
    expect(text).toContain('Prompt attack guardrail enforced (PromptInjection.Direct)');
    expect(text).toContain('Pass');
    expect(text).toContain('Action required');
  });

  it('keeps GuardDuty recommendations on the custom page', () => {
    const text = draw(REPORT).container.textContent;

    expect(text).toContain('Protection plan recommendations');
    expect(text).toContain('Enforce a Bedrock Guardrail prompt attack filter');
    expect(text).toContain('Enable GuardDuty Runtime Monitoring');
  });

  it('leaves custom-page carriers out of the recommendations', () => {
    const text = draw(REPORT).container.textContent;

    expect(text).not.toContain('AI Protection status');
    expect(text).not.toContain('AiProtectionStatus');
  });

  it('omits the AI Protection table when the scan has no AI Protection data', () => {
    const report = {
      guardduty: {
        summary: {},
        detail: { 'us-east-1': { 'Detector::abc123': {} } }
      }
    };
    const text = draw(report).container.textContent;

    expect(text).not.toContain('AI Protection finding type coverage');
    expect(text).not.toContain('Protection plan recommendations');
  });
});
