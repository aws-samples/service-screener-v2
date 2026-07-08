import re
import botocore

from services.Evaluator import Evaluator


class EcsTaskDefinition(Evaluator):
    """
    Task-definition-level ECS checks (19 total: 16 Tier 1 + 3 Tier 2).

    Input:
      task_def                 -- describe_task_definition['taskDefinition']
      secrets_client           -- boto3 secretsmanager client (for check 35)
      ssm_client               -- boto3 ssm client (for check 35)
      cluster_has_fargate_cmk  -- bool, True if any cluster in region sets
                                  fargateEphemeralStorageKmsKeyId (used by check 42)
    """

    # Check IDs from spec
    # 20 ecsTaskDefinitionNonRootUser
    # 21 ecsTaskDefinitionNoPrivilegedContainers
    # 22 ecsTaskDefinitionReadonlyRootFilesystem
    # 23 ecsTaskDefinitionLoggingConfigured
    # 24 ecsTaskDefinitionNoSecretsInEnvVars
    # 25 ecsTaskDefinitionHostNetworkModeUser
    # 26 ecsTaskDefinitionSeparateTaskAndExecutionRoles
    # 27 ecsTaskDefinitionHealthCheckDefined
    # 28 ecsTaskDefinitionResourceLimits
    # 29 ecsTaskDefinitionNoHostPidMode
    # 30 ecsTaskDefinitionNoHostIpcMode
    # 31 ecsTaskDefinitionLinuxCapabilities
    # 32 ecsTaskDefinitionNoLatestTag
    # 33 ecsTaskDefinitionEcrImageSource
    # 34 ecsTaskDefinitionLogDriverAwslogs
    # 35 ecsTaskDefinitionSecretReferences
    # 40 ecsTaskDefinitionSensitiveHostPaths (T2)
    # 41 ecsTaskDefinitionUlimitsConfigured (T2)
    # 42 ecsTaskDefinitionEphemeralStorageEncryption (T2)

    ROOT_USER_VALUES = {'', 'root', '0', '0:0'}

    # Secret detection in ENV var NAMES (values are harder without false-positives)
    SECRET_NAME_PATTERNS = [
        re.compile(r'AWS_SECRET_ACCESS_KEY', re.IGNORECASE),
        re.compile(r'AWS_SESSION_TOKEN', re.IGNORECASE),
        re.compile(r'PASSWORD', re.IGNORECASE),
        re.compile(r'PASSWD', re.IGNORECASE),
        re.compile(r'(^|_)SECRET($|_)', re.IGNORECASE),
        re.compile(r'API[_-]?KEY', re.IGNORECASE),
        re.compile(r'PRIVATE[_-]?KEY', re.IGNORECASE),
        re.compile(r'(^|_)TOKEN($|_)', re.IGNORECASE),
        re.compile(r'CREDENTIALS?', re.IGNORECASE),
        re.compile(r'CONNECTION[_-]?STRING', re.IGNORECASE),
        re.compile(r'AUTH[_-]?KEY', re.IGNORECASE),
    ]

    # Env-var names that superficially look sensitive but are typically benign
    # (avoid false positives).
    BENIGN_NAMES = {
        'AWS_DEFAULT_REGION',
        'AWS_REGION',
        'AWS_EXECUTION_ENV',
        'AWS_LAMBDA_FUNCTION_NAME',
    }

    # AWS access-key-id value pattern
    AWS_ACCESS_KEY_ID_RE = re.compile(r'^(AKIA|ASIA)[0-9A-Z]{16}$')

    DANGEROUS_CAPABILITIES = {
        'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_RAWIO',
        'DAC_OVERRIDE', 'NET_RAW', 'ALL',
    }

    ECR_HOSTNAME_RE = re.compile(r'^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/', re.IGNORECASE)

    DURABLE_LOG_DRIVERS = {'awslogs', 'awsfirelens', 'splunk'}

    SENSITIVE_HOST_PATHS = {
        '/', '/etc', '/proc', '/sys', '/root',
        '/var/run/docker.sock', '/var/run', '/dev',
    }

    ULIMIT_NOFILE_MAX = 65536
    ULIMIT_NPROC_MAX = 4096

    def __init__(self, task_def, secrets_client, ssm_client, cluster_has_fargate_cmk):
        super().__init__()
        self.td = task_def or {}
        self.secretsClient = secrets_client
        self.ssmClient = ssm_client
        self.cluster_has_fargate_cmk = bool(cluster_has_fargate_cmk)

        family = self.td.get('family', 'unknown')
        rev = self.td.get('revision', '?')
        self._resourceName = f"TaskDef::{family}:{rev}"

        self.addII('family', family)
        self.addII('revision', rev)
        self.addII('taskDefinitionArn', self.td.get('taskDefinitionArn', 'N/A'))
        self.addII('networkMode', self.td.get('networkMode', 'bridge'))
        self.addII('requiresCompatibilities',
                   ','.join(self.td.get('requiresCompatibilities') or []) or 'N/A')

        self._containers = self.td.get('containerDefinitions') or []

    # ------------------------------------------------------------------ #
    # #20 ecsTaskDefinitionNonRootUser
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionNonRootUser(self):
        offenders = []
        for c in self._containers:
            user = (c.get('user') or '').strip()
            # user field can be "uid[:gid]" — first part is uid
            uid_part = user.split(':', 1)[0].lower()
            if uid_part in self.ROOT_USER_VALUES:
                offenders.append(f"{c.get('name', '?')} (user='{user}')")
        if offenders:
            self.results['ecsTaskDefinitionNonRootUser'] = [
                -1, "Container(s) running as root: " + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionNonRootUser'] = [
                1, f"All {len(self._containers)} container(s) run as non-root"
            ]

    # ------------------------------------------------------------------ #
    # #21 ecsTaskDefinitionNoPrivilegedContainers
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionNoPrivilegedContainers(self):
        offenders = [c.get('name', '?') for c in self._containers if c.get('privileged') is True]
        if offenders:
            self.results['ecsTaskDefinitionNoPrivilegedContainers'] = [
                -1, "Privileged container(s): " + ", ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionNoPrivilegedContainers'] = [
                1, "No privileged containers"
            ]

    # ------------------------------------------------------------------ #
    # #22 ecsTaskDefinitionReadonlyRootFilesystem
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionReadonlyRootFilesystem(self):
        writable = []
        for c in self._containers:
            if not c.get('readonlyRootFilesystem'):
                writable.append(c.get('name', '?'))
        if writable:
            self.results['ecsTaskDefinitionReadonlyRootFilesystem'] = [
                -1, "Writable root FS on: " + ", ".join(writable[:5])
            ]
        else:
            self.results['ecsTaskDefinitionReadonlyRootFilesystem'] = [
                1, "All containers have readonlyRootFilesystem=true"
            ]

    # ------------------------------------------------------------------ #
    # #23 ecsTaskDefinitionLoggingConfigured
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionLoggingConfigured(self):
        missing = [c.get('name', '?') for c in self._containers
                   if not c.get('logConfiguration')]
        if missing:
            self.results['ecsTaskDefinitionLoggingConfigured'] = [
                -1, "Container(s) without logConfiguration: " + ", ".join(missing[:5])
            ]
        else:
            self.results['ecsTaskDefinitionLoggingConfigured'] = [
                1, "All containers have logConfiguration"
            ]

    # ------------------------------------------------------------------ #
    # #24 ecsTaskDefinitionNoSecretsInEnvVars
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionNoSecretsInEnvVars(self):
        findings = []
        for c in self._containers:
            cname = c.get('name', '?')
            env = c.get('environment') or []
            for pair in env:
                if not isinstance(pair, dict):
                    continue
                key = pair.get('name', '')
                val = pair.get('value', '')
                if not key or key in self.BENIGN_NAMES:
                    # Value-side check: AWS access key ID pattern is unmistakable
                    if val and self.AWS_ACCESS_KEY_ID_RE.match(str(val)):
                        findings.append(f"{cname}:{key or '(unnamed)'} (AWS access key value)")
                    continue
                for pat in self.SECRET_NAME_PATTERNS:
                    if pat.search(key):
                        findings.append(f"{cname}:{key}")
                        break
                # Also flag obvious AWS access key values regardless of name
                if val and self.AWS_ACCESS_KEY_ID_RE.match(str(val)):
                    findings.append(f"{cname}:{key} (AWS access key value)")
        if findings:
            self.results['ecsTaskDefinitionNoSecretsInEnvVars'] = [
                -1,
                f"Secret-like env var(s): {', '.join(findings[:5])}"
                + (f" (+{len(findings)-5} more)" if len(findings) > 5 else "")
            ]
        else:
            self.results['ecsTaskDefinitionNoSecretsInEnvVars'] = [
                1, "No secret-pattern env vars detected"
            ]

    # ------------------------------------------------------------------ #
    # #25 ecsTaskDefinitionHostNetworkModeUser
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionHostNetworkModeUser(self):
        nm = self.td.get('networkMode') or 'bridge'
        if nm != 'host':
            self.results['ecsTaskDefinitionHostNetworkModeUser'] = [
                0, f"networkMode={nm} — host-mode check N/A"
            ]
            return
        offenders = []
        for c in self._containers:
            if c.get('privileged') is True:
                continue
            user = (c.get('user') or '').strip()
            uid_part = user.split(':', 1)[0].lower()
            if uid_part in self.ROOT_USER_VALUES:
                offenders.append(f"{c.get('name', '?')} (user='{user}')")
        if offenders:
            self.results['ecsTaskDefinitionHostNetworkModeUser'] = [
                -1,
                "host networkMode with root-user, non-privileged container(s): "
                + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionHostNetworkModeUser'] = [
                1, "host networkMode but all containers non-root or privileged"
            ]

    # ------------------------------------------------------------------ #
    # #26 ecsTaskDefinitionSeparateTaskAndExecutionRoles
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionSeparateTaskAndExecutionRoles(self):
        task_role = self.td.get('taskRoleArn')
        exec_role = self.td.get('executionRoleArn')
        if not task_role:
            self.results['ecsTaskDefinitionSeparateTaskAndExecutionRoles'] = [
                -1, "No taskRoleArn — workload has no scoped IAM role"
            ]
        elif exec_role and task_role == exec_role:
            self.results['ecsTaskDefinitionSeparateTaskAndExecutionRoles'] = [
                -1, "taskRoleArn == executionRoleArn — workload inherits execution privileges"
            ]
        else:
            self.results['ecsTaskDefinitionSeparateTaskAndExecutionRoles'] = [
                1, "taskRoleArn and executionRoleArn are distinct"
            ]

    # ------------------------------------------------------------------ #
    # #27 ecsTaskDefinitionHealthCheckDefined
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionHealthCheckDefined(self):
        any_hc = any(bool(c.get('healthCheck')) for c in self._containers)
        if any_hc:
            n = sum(1 for c in self._containers if c.get('healthCheck'))
            self.results['ecsTaskDefinitionHealthCheckDefined'] = [
                1, f"{n}/{len(self._containers)} container(s) define healthCheck"
            ]
        else:
            self.results['ecsTaskDefinitionHealthCheckDefined'] = [
                -1, "No container defines a healthCheck"
            ]

    # ------------------------------------------------------------------ #
    # #28 ecsTaskDefinitionResourceLimits
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionResourceLimits(self):
        cpu = self.td.get('cpu')
        mem = self.td.get('memory')
        if cpu and mem:
            self.results['ecsTaskDefinitionResourceLimits'] = [
                1, f"Task cpu={cpu}, memory={mem}"
            ]
        else:
            missing = []
            if not cpu:
                missing.append('cpu')
            if not mem:
                missing.append('memory')
            self.results['ecsTaskDefinitionResourceLimits'] = [
                -1, f"Task-level {', '.join(missing)} not set"
            ]

    # ------------------------------------------------------------------ #
    # #29 ecsTaskDefinitionNoHostPidMode
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionNoHostPidMode(self):
        if self.td.get('pidMode') == 'host':
            self.results['ecsTaskDefinitionNoHostPidMode'] = [
                -1, "pidMode=host — container escape vector"
            ]
        else:
            self.results['ecsTaskDefinitionNoHostPidMode'] = [
                1, f"pidMode={self.td.get('pidMode') or 'unset'}"
            ]

    # ------------------------------------------------------------------ #
    # #30 ecsTaskDefinitionNoHostIpcMode
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionNoHostIpcMode(self):
        if self.td.get('ipcMode') == 'host':
            self.results['ecsTaskDefinitionNoHostIpcMode'] = [
                -1, "ipcMode=host — shared-memory attack surface"
            ]
        else:
            self.results['ecsTaskDefinitionNoHostIpcMode'] = [
                1, f"ipcMode={self.td.get('ipcMode') or 'unset'}"
            ]

    # ------------------------------------------------------------------ #
    # #31 ecsTaskDefinitionLinuxCapabilities
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionLinuxCapabilities(self):
        offenders = []
        for c in self._containers:
            lp = c.get('linuxParameters') or {}
            caps = (lp.get('capabilities') or {})
            add = caps.get('add') or []
            dangerous = [cap for cap in add if cap in self.DANGEROUS_CAPABILITIES]
            if dangerous:
                offenders.append(f"{c.get('name', '?')} adds {','.join(dangerous)}")
        if offenders:
            self.results['ecsTaskDefinitionLinuxCapabilities'] = [
                -1, "Dangerous Linux capabilities: " + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionLinuxCapabilities'] = [
                1, "No dangerous Linux capabilities added"
            ]

    # ------------------------------------------------------------------ #
    # #32 ecsTaskDefinitionNoLatestTag
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionNoLatestTag(self):
        offenders = []
        for c in self._containers:
            image = c.get('image') or ''
            if not image:
                continue
            # Strip host prefix, keep the ref after '/'
            # Examples:
            #   nginx  -> tag missing
            #   nginx:latest -> :latest
            #   123.dkr.ecr.us-east-1.amazonaws.com/myapp:v1 -> :v1 OK
            #   myrepo/myapp@sha256:... -> digest OK
            # We only care about the final `:tag` (or absence of tag/digest).
            if '@' in image:
                # digest pinned — fine
                continue
            # split the *last* segment (after final /) to find :
            last_seg = image.rsplit('/', 1)[-1]
            if ':' in last_seg:
                tag = last_seg.rsplit(':', 1)[1]
                if tag.lower() == 'latest':
                    offenders.append(f"{c.get('name', '?')} ({image})")
            else:
                # no explicit tag — implicit :latest
                offenders.append(f"{c.get('name', '?')} ({image} — no tag)")
        if offenders:
            self.results['ecsTaskDefinitionNoLatestTag'] = [
                -1, "Mutable/implicit :latest tag on: " + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionNoLatestTag'] = [
                1, "All container images use explicit versioned tags or digests"
            ]

    # ------------------------------------------------------------------ #
    # #33 ecsTaskDefinitionEcrImageSource
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionEcrImageSource(self):
        non_ecr = []
        for c in self._containers:
            image = c.get('image') or ''
            if not image:
                continue
            # ECR-public: public.ecr.aws/... — treat as ECR-family (AWS-controlled)
            if image.lower().startswith('public.ecr.aws/'):
                continue
            if not self.ECR_HOSTNAME_RE.match(image):
                non_ecr.append(f"{c.get('name', '?')} ({image})")
        if non_ecr:
            self.results['ecsTaskDefinitionEcrImageSource'] = [
                -1, "Non-ECR image source(s): " + "; ".join(non_ecr[:5])
            ]
        else:
            self.results['ecsTaskDefinitionEcrImageSource'] = [
                1, "All container images sourced from ECR"
            ]

    # ------------------------------------------------------------------ #
    # #34 ecsTaskDefinitionLogDriverAwslogs
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionLogDriverAwslogs(self):
        offenders = []
        for c in self._containers:
            lc = c.get('logConfiguration') or {}
            driver = lc.get('logDriver')
            if not driver:
                continue  # covered by check #23
            if driver not in self.DURABLE_LOG_DRIVERS:
                offenders.append(f"{c.get('name', '?')} ({driver})")
        if offenders:
            self.results['ecsTaskDefinitionLogDriverAwslogs'] = [
                -1, "Non-durable log driver(s): " + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionLogDriverAwslogs'] = [
                1, "All log drivers are durable (awslogs / awsfirelens / splunk)"
            ]

    # ------------------------------------------------------------------ #
    # #35 ecsTaskDefinitionSecretReferences
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionSecretReferences(self):
        refs = []
        for c in self._containers:
            for s in (c.get('secrets') or []):
                vf = s.get('valueFrom')
                if vf:
                    refs.append((c.get('name', '?'), s.get('name', '?'), vf))
        if not refs:
            self.results['ecsTaskDefinitionSecretReferences'] = [
                0, "Task definition references no secrets"
            ]
            return

        broken = []
        checked = 0
        # Cap probes to avoid explosion on very large task defs
        MAX_PROBES = 10
        for cname, sname, vf in refs[:MAX_PROBES]:
            status = self._probeSecret(vf)
            checked += 1
            if status == 'broken':
                broken.append(f"{cname}:{sname} → {vf}")
            elif status == 'unknown':
                # Skip malformed/unknown ARNs; don't fail the check on lookup issues.
                continue
        if broken:
            self.results['ecsTaskDefinitionSecretReferences'] = [
                -1,
                f"{len(broken)} broken secret reference(s): {'; '.join(broken[:3])}"
            ]
        else:
            self.results['ecsTaskDefinitionSecretReferences'] = [
                1, f"All {checked} probed secret reference(s) resolve"
            ]

    def _probeSecret(self, value_from):
        """
        Return 'ok' | 'broken' | 'unknown'.

        Recognised valueFrom formats:
          arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME[-suffix][:JSONKEY::]
          arn:aws:ssm:REGION:ACCOUNT:parameter/PARAM_NAME
          PARAM_NAME (plain string — SSM parameter, same-region)
        """
        if not value_from:
            return 'unknown'
        try:
            if 'secretsmanager:' in value_from and ':secret:' in value_from:
                # Strip optional trailing :JSONKEY::VERSION_STAGE:VERSION_ID
                secret_id = value_from
                # Try DescribeSecret with the ARN base (drop suffix parts)
                base = value_from.split(':secret:', 1)[0] + ':secret:' + \
                       value_from.split(':secret:', 1)[1].split(':', 1)[0]
                try:
                    self.secretsClient.describe_secret(SecretId=base)
                    return 'ok'
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    if code in ('ResourceNotFoundException',):
                        return 'broken'
                    return 'unknown'
            elif ':ssm:' in value_from and ':parameter/' in value_from:
                param_name = value_from.split(':parameter', 1)[1]
                # get_parameter expects the name (with leading /)
                if not param_name.startswith('/'):
                    param_name = '/' + param_name
                try:
                    self.ssmClient.get_parameter(Name=param_name, WithDecryption=False)
                    return 'ok'
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    if code in ('ParameterNotFound',):
                        return 'broken'
                    return 'unknown'
            elif value_from.startswith('/') or not value_from.startswith('arn:'):
                # Plain SSM parameter name
                try:
                    self.ssmClient.get_parameter(Name=value_from, WithDecryption=False)
                    return 'ok'
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    if code in ('ParameterNotFound',):
                        return 'broken'
                    return 'unknown'
            else:
                return 'unknown'
        except Exception:
            return 'unknown'

    # ------------------------------------------------------------------ #
    # #40 ecsTaskDefinitionSensitiveHostPaths (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionSensitiveHostPaths(self):
        volumes = self.td.get('volumes') or []
        offenders = []
        for v in volumes:
            host = v.get('host') or {}
            sp = host.get('sourcePath')
            if not sp:
                continue
            # Exact match or start-of-path match against sensitive prefixes
            sp_norm = sp.rstrip('/') or '/'
            if sp_norm in self.SENSITIVE_HOST_PATHS or any(
                sp_norm == p or sp_norm.startswith(p + '/') for p in self.SENSITIVE_HOST_PATHS
            ):
                offenders.append(f"{v.get('name', '?')} → {sp}")
        if offenders:
            self.results['ecsTaskDefinitionSensitiveHostPaths'] = [
                -1, "Sensitive host path bind-mount(s): " + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionSensitiveHostPaths'] = [
                1, "No sensitive host paths bind-mounted"
            ]

    # ------------------------------------------------------------------ #
    # #41 ecsTaskDefinitionUlimitsConfigured (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionUlimitsConfigured(self):
        offenders = []
        for c in self._containers:
            for u in (c.get('ulimits') or []):
                name = u.get('name')
                hard = u.get('hardLimit')
                if hard is None:
                    continue
                if name == 'nofile' and hard > self.ULIMIT_NOFILE_MAX:
                    offenders.append(f"{c.get('name', '?')}: nofile.hard={hard}")
                elif name == 'nproc' and hard > self.ULIMIT_NPROC_MAX:
                    offenders.append(f"{c.get('name', '?')}: nproc.hard={hard}")
        if offenders:
            self.results['ecsTaskDefinitionUlimitsConfigured'] = [
                -1, "Excessive ulimit(s): " + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecsTaskDefinitionUlimitsConfigured'] = [
                1, "All ulimits within recommended bounds"
            ]

    # ------------------------------------------------------------------ #
    # #42 ecsTaskDefinitionEphemeralStorageEncryption (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsTaskDefinitionEphemeralStorageEncryption(self):
        eph = (self.td.get('ephemeralStorage') or {}).get('sizeInGiB')
        # Fargate-only feature
        requires = self.td.get('requiresCompatibilities') or []
        if 'FARGATE' not in requires:
            self.results['ecsTaskDefinitionEphemeralStorageEncryption'] = [
                0, "Not a Fargate task definition"
            ]
            return
        if not eph or eph <= 20:
            self.results['ecsTaskDefinitionEphemeralStorageEncryption'] = [
                1, f"Ephemeral storage {eph or 'default'} GiB — CMK not required"
            ]
            return
        if self.cluster_has_fargate_cmk:
            self.results['ecsTaskDefinitionEphemeralStorageEncryption'] = [
                1, f"Ephemeral storage {eph} GiB, cluster provides fargateEphemeralStorageKmsKeyId"
            ]
        else:
            self.results['ecsTaskDefinitionEphemeralStorageEncryption'] = [
                -1,
                f"Ephemeral storage {eph} GiB (> 20 default) but no cluster in region sets "
                "fargateEphemeralStorageKmsKeyId"
            ]
