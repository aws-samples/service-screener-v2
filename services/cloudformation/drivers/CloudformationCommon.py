import json

from services.Evaluator import Evaluator


class CloudformationCommon(Evaluator):
    """
    Account/region-level CloudFormation checks, run once per region.

    Input (hydrated read-only by services/cloudformation/Cloudformation.py):
      detail['_region']
      detail['_hooks']      -- list of {'TypeName', 'TypeArn', 'Configurations':
                               [Configuration JSON strings], 'ConfigError': code}
                               for every HOOK type visible in the account and
                               Region (registered private hooks and activated
                               public hooks, which is where Guard / Lambda hooks
                               and Control Tower proactive controls surface)
      detail['_hooksError'] -- error code when list_types itself failed, else None

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, detail):
        super().__init__()
        self.detail = detail
        self.region = detail.get('_region', 'N/A')
        self._resourceName = f"CloudFormation::{self.region}"
        self.hooks = detail.get('_hooks') or []
        self.hooksError = detail.get('_hooksError')

        self.addII('region', self.region)
        self.addII('hookCount', str(len(self.hooks)))

    # ------------------------------------------------------------------ #
    # Proactive controls: at least one CloudFormation hook ENABLED
    # ------------------------------------------------------------------ #
    @staticmethod
    def hookConfigEnabled(configuration):
        """
        True when a hook type configuration (the JSON string returned by
        batch_describe_type_configurations) turns the hook on for stack
        operations. HookInvocationStatus defaults to DISABLED, so an activated
        hook with no configuration does nothing.
        """
        try:
            cfg = json.loads(configuration) if isinstance(configuration, str) \
                else (configuration or {})
        except (TypeError, ValueError):
            return False
        hookCfg = ((cfg.get('CloudFormationConfiguration') or {})
                   .get('HookConfiguration') or {})
        if str(hookCfg.get('HookInvocationStatus', '')).upper() != 'ENABLED':
            return False
        ## Legacy schema: TargetStacks NONE means "never invoked for stacks".
        ## Newer configurations use TargetOperations instead.
        if (str(hookCfg.get('TargetStacks', '')).upper() == 'NONE'
                and not hookCfg.get('TargetOperations')):
            return False
        return True

    def _checkCfnNoProactiveHooks(self):
        key = 'cfnNoProactiveHooks'
        if self.hooksError:
            self.results[key] = [
                0, f"Unable to evaluate ({self.hooksError})"
            ]
            return

        enabled, configUnknown = [], []
        for h in self.hooks:
            name = h.get('TypeName') or h.get('TypeArn') or '?'
            if any(self.hookConfigEnabled(c)
                   for c in h.get('Configurations') or []):
                enabled.append(name)
            elif h.get('ConfigError'):
                configUnknown.append((name, h.get('ConfigError')))

        if enabled:
            self.results[key] = [
                1,
                f"{len(enabled)} CloudFormation hook(s) enabled in "
                f"{self.region}: " + self._joinNames(enabled)
            ]
        elif configUnknown:
            codes = sorted({c for _, c in configUnknown})
            self.results[key] = [
                0,
                f"Unable to evaluate ({', '.join(codes)}) — configuration of "
                + self._joinNames([n for n, _ in configUnknown])
                + " could not be read"
            ]
        elif self.hooks:
            self.results[key] = [
                -1,
                f"{len(self.hooks)} CloudFormation hook(s) are registered or "
                f"activated in {self.region} ("
                + self._joinNames([h.get('TypeName') or '?' for h in self.hooks])
                + ") but none has HookInvocationStatus ENABLED — no proactive "
                "control evaluates stack operations before resources are "
                "provisioned"
            ]
        else:
            self.results[key] = [
                -1,
                f"No CloudFormation hook (Guard, Lambda, third-party or Control "
                f"Tower proactive control) is activated in {self.region} — "
                "non-compliant resources are only caught after they are deployed, "
                "if at all"
            ]

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
