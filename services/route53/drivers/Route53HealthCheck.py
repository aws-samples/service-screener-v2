from services.Evaluator import Evaluator


class Route53HealthCheck(Evaluator):
    """
    Route 53 health-check checks.

    Input:
      hc -- one item from list_health_checks. Structure:
        {
          'Id': '...',
          'CallerReference': '...',
          'HealthCheckConfig': { 'Type': 'HTTP'|'HTTPS'|'HTTP_STR_MATCH'|
                                          'HTTPS_STR_MATCH'|'TCP'|'CLOUDWATCH_METRIC'|
                                          'CALCULATED'|...,
                                 'ResourcePath', 'FullyQualifiedDomainName',
                                 'IPAddress', 'Port', 'RequestInterval',
                                 'FailureThreshold', 'MeasureLatency', 'Inverted',
                                 'Disabled', 'EnableSNI', 'ChildHealthChecks',
                                 'HealthThreshold', 'AlarmIdentifier', ... },
          'HealthCheckVersion': int,
          'CloudWatchAlarmConfiguration': { ... } | absent,
          'LinkedService': { ... } | absent
        }
      route53Client -- boto3 route53 client (unused, kept for parity).
    """

    HTTP_TYPES = {'HTTP', 'HTTP_STR_MATCH'}
    HTTPS_TYPES = {'HTTPS', 'HTTPS_STR_MATCH'}
    ENDPOINT_TYPES = HTTP_TYPES | HTTPS_TYPES | {'TCP'}
    # These types are inherently alarm-driven and are exempt from #8 (NoAlarm).
    ALARM_EXEMPT_TYPES = {'CLOUDWATCH_METRIC', 'CALCULATED', 'RECOVERY_CONTROL'}

    FAST_INTERVAL = 10
    STANDARD_INTERVAL = 30

    LOW_FAILURE_THRESHOLD = 1
    RECOMMENDED_MIN_THRESHOLD = 3

    def __init__(self, hc, route53Client):
        super().__init__()
        self.hc = hc
        self.route53Client = route53Client

        self.hcId = hc.get('Id', 'unknown')
        self.config = hc.get('HealthCheckConfig') or {}
        self.hcType = self.config.get('Type', 'UNKNOWN')
        self._resourceName = self.hcId

        # Prefer FQDN if set, else IP + Port, else the raw ID.
        fqdn = self.config.get('FullyQualifiedDomainName')
        ip = self.config.get('IPAddress')
        port = self.config.get('Port')
        display = fqdn or (f"{ip}:{port}" if ip and port else self.hcId)

        self.addII('id', self.hcId)
        self.addII('type', self.hcType)
        self.addII('endpoint', display)
        self.addII('disabled', str(bool(self.config.get('Disabled', False))))
        self.addII('requestInterval', self.config.get('RequestInterval', 'N/A'))
        self.addII('failureThreshold', self.config.get('FailureThreshold', 'N/A'))
        self.addII('cloudWatchAlarm',
                   'true' if hc.get('CloudWatchAlarmConfiguration') else 'false')

    # ------------------------------------------------------------------ #
    # 7. Health check probes over HTTP
    # ------------------------------------------------------------------ #
    def _checkRoute53HealthCheckUsingHttp(self):
        if self.hcType in self.HTTP_TYPES:
            self.results['route53HealthCheckUsingHttp'] = [
                -1, f"Health check Type={self.hcType} — probes over cleartext HTTP"
            ]
        elif self.hcType in self.HTTPS_TYPES:
            self.results['route53HealthCheckUsingHttp'] = [
                1, f"Health check Type={self.hcType}"
            ]
        else:
            # TCP / CLOUDWATCH_METRIC / CALCULATED — not applicable.
            self.results['route53HealthCheckUsingHttp'] = [
                0, f"Type={self.hcType} — HTTP/HTTPS check not applicable"
            ]

    # ------------------------------------------------------------------ #
    # 8. Endpoint health check without CloudWatch alarm
    # ------------------------------------------------------------------ #
    def _checkRoute53HealthCheckNoAlarm(self):
        if self.hcType in self.ALARM_EXEMPT_TYPES:
            self.results['route53HealthCheckNoAlarm'] = [
                0, f"Type={self.hcType} — inherently alarm-driven"
            ]
            return
        if self.hc.get('CloudWatchAlarmConfiguration'):
            alarm = self.hc.get('CloudWatchAlarmConfiguration') or {}
            self.results['route53HealthCheckNoAlarm'] = [
                1,
                f"CloudWatch alarm attached: {alarm.get('MetricName', 'unknown')}"
            ]
        else:
            self.results['route53HealthCheckNoAlarm'] = [
                -1, "No CloudWatchAlarmConfiguration — failures will not alert"
            ]

    # ------------------------------------------------------------------ #
    # 13. Slow (30s) request interval
    # ------------------------------------------------------------------ #
    def _checkRoute53HealthCheckSlowInterval(self):
        # CLOUDWATCH_METRIC / CALCULATED types don't have RequestInterval.
        interval = self.config.get('RequestInterval')
        if interval is None:
            self.results['route53HealthCheckSlowInterval'] = [
                0, f"Type={self.hcType} — no RequestInterval"
            ]
            return
        try:
            iv = int(interval)
        except (TypeError, ValueError):
            self.results['route53HealthCheckSlowInterval'] = [
                0, f"Unparseable RequestInterval={interval!r}"
            ]
            return
        if iv <= self.FAST_INTERVAL:
            self.results['route53HealthCheckSlowInterval'] = [
                1, f"RequestInterval={iv}s (fast)"
            ]
        else:
            self.results['route53HealthCheckSlowInterval'] = [
                -1,
                f"RequestInterval={iv}s — consider 10s for faster failover"
            ]

    # ------------------------------------------------------------------ #
    # 14. Failure threshold too low
    # ------------------------------------------------------------------ #
    def _checkRoute53HealthCheckLowFailureThreshold(self):
        threshold = self.config.get('FailureThreshold')
        if threshold is None:
            self.results['route53HealthCheckLowFailureThreshold'] = [
                0, f"Type={self.hcType} — no FailureThreshold"
            ]
            return
        try:
            t = int(threshold)
        except (TypeError, ValueError):
            self.results['route53HealthCheckLowFailureThreshold'] = [
                0, f"Unparseable FailureThreshold={threshold!r}"
            ]
            return
        if t <= self.LOW_FAILURE_THRESHOLD:
            self.results['route53HealthCheckLowFailureThreshold'] = [
                -1,
                f"FailureThreshold={t} — will flap on transient errors "
                f"(recommend ≥ {self.RECOMMENDED_MIN_THRESHOLD})"
            ]
        else:
            self.results['route53HealthCheckLowFailureThreshold'] = [
                1, f"FailureThreshold={t}"
            ]

    # ------------------------------------------------------------------ #
    # 17. Health check disabled
    # ------------------------------------------------------------------ #
    def _checkRoute53HealthCheckDisabled(self):
        # Disabled key may be absent (defaults to False).
        if self.config.get('Disabled', False):
            self.results['route53HealthCheckDisabled'] = [
                -1, "Disabled=true — failover will not fire"
            ]
        else:
            self.results['route53HealthCheckDisabled'] = [
                1, "Health check is enabled"
            ]

    # ------------------------------------------------------------------ #
    # 22. HTTPS health check without SNI
    # ------------------------------------------------------------------ #
    def _checkRoute53HealthCheckSniDisabled(self):
        if self.hcType not in self.HTTPS_TYPES:
            self.results['route53HealthCheckSniDisabled'] = [
                0, f"Type={self.hcType} — SNI not applicable"
            ]
            return
        # EnableSNI defaults to True on HTTPS in newer AWS deployments; only
        # fail when it's explicitly False.
        if self.config.get('EnableSNI', True):
            self.results['route53HealthCheckSniDisabled'] = [
                1, "EnableSNI=true"
            ]
        else:
            self.results['route53HealthCheckSniDisabled'] = [
                -1, "EnableSNI=false — may validate wrong certificate"
            ]
