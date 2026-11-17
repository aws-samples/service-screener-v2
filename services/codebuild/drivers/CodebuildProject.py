import json
import re
import urllib.parse

import botocore

from services.Evaluator import Evaluator


class CodebuildProject(Evaluator):
    """
    Per-project CodeBuild checks (17 of the 18).

    Input:
      project -- a batch_get_projects entry plus '_tags' (normalised to
                 Key/Value) and '_region', from services/codebuild/Codebuild.py.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.

    SECRET HANDLING: _checkCbPlaintextCredentialsInEnvVars and
    _checkCbSourceUrlCredentials both detect credentials in project config. They
    report only WHERE the credential is (the variable name, or which source
    field), never the value. A scan report must not become a second copy of the
    leak, and reports get pasted into tickets and chat.
    """

    ## Environment variable names that indicate a credential when stored as
    ## PLAINTEXT. AWS key names are matched exactly because they are
    ## unambiguous; the rest are substring fragments.
    EXACT_CREDENTIAL_NAMES = frozenset([
        'aws_access_key_id',
        'aws_secret_access_key',
        'aws_session_token',
    ])

    CREDENTIAL_NAME_FRAGMENTS = (
        'secret', 'password', 'passwd', 'token', 'credential', 'privatekey',
        'private_key', 'apikey', 'api_key', 'accesskey', 'access_key',
        'auth', 'cert',
    )

    ## Environment variable types that resolve at build time from a secure
    ## store rather than embedding the value in the project definition.
    SECURE_ENV_TYPES = frozenset(['PARAMETER_STORE', 'SECRETS_MANAGER'])

    ## Source types whose location is a URL that could carry inline credentials.
    URL_SOURCE_TYPES = frozenset(['GITHUB', 'GITHUB_ENTERPRISE', 'BITBUCKET',
                                  'CODECOMMIT', 'S3'])

    ## https://user:password@host — the form FSBP CodeBuild.1 looks for. The
    ## userinfo segment must contain a colon, otherwise it is just a username,
    ## which is not a credential.
    URL_CREDENTIAL_PATTERN = re.compile(r'://[^/\s:@]+:[^/\s@]+@')

    ## CodeBuild curated images that AWS has retired or that pin an end-of-life
    ## toolchain. Matched as substrings against environment.image, which has the
    ## form 'aws/codebuild/standard:5.0' (verified live) -- NOT the
    ## 'ubuntu:standard:5.0' short form. standard:5.0 and earlier are Ubuntu
    ## images past EOL; standard:6.0/7.0 are current.
    DEPRECATED_IMAGE_FRAGMENTS = (
        'aws/codebuild/standard:1.0', 'aws/codebuild/standard:2.0',
        'aws/codebuild/standard:3.0', 'aws/codebuild/standard:4.0',
        'aws/codebuild/standard:5.0',
        'aws/codebuild/amazonlinux2-x86_64-standard:1.0',
        'aws/codebuild/amazonlinux2-x86_64-standard:2.0',
        'aws/codebuild/amazonlinux2-x86_64-standard:3.0',
        'aws/codebuild/windows-base:1.0', 'aws/codebuild/windows-base:2.0',
    )

    MAX_NAMES_IN_MESSAGE = 5

    ## Pull-request webhook events that build code which has NOT been reviewed
    ## and merged. PULL_REQUEST_MERGED builds the base branch after merge, so it
    ## is excluded. Matched case-insensitively against the comma-separated
    ## EVENT pattern.
    UNREVIEWED_PR_EVENTS = frozenset([
        'PULL_REQUEST_CREATED', 'PULL_REQUEST_UPDATED',
        'PULL_REQUEST_REOPENED', 'PULL_REQUEST_CLOSED',
    ])

    ## pullRequestBuildPolicy.requiresCommentApproval values that gate PR
    ## builds behind an approving comment from a repository collaborator.
    PR_APPROVAL_GATED = frozenset(['ALL_PULL_REQUESTS', 'FORK_PULL_REQUESTS'])

    ## pullRequestBuildPolicy.approverRoles below write access. A comment
    ## approval any reader/triager can give is not a trust gate.
    LOW_TRUST_APPROVER_ROLES = frozenset([
        'GITHUB_READ', 'GITHUB_TRIAGE',
        'GITLAB_GUEST', 'GITLAB_PLANNER', 'GITLAB_REPORTER',
        'BITBUCKET_READ',
    ])

    ## Webhook.status values for which the webhook does not trigger builds.
    WEBHOOK_INACTIVE = frozenset(['CREATE_FAILED', 'DELETING'])

    IAM_DENIED_CODES = ('AccessDenied', 'AccessDeniedException',
                        'UnauthorizedOperation', 'AuthorizationError')

    def __init__(self, project, cbClient, iamClient=None, roleCache=None,
                 reportIndexFn=None):
        super().__init__()
        self.project = project
        self.cbClient = cbClient
        self.iamClient = iamClient
        ## dict shared by every project in the region (role ARN -> result)
        self.roleCache = roleCache if roleCache is not None else {}
        ## callable returning the lazily built report-group index from
        ## services/codebuild/Codebuild.py (_getReportIndex)
        self.reportIndexFn = reportIndexFn

        self.name = project.get('name', 'unknown')
        self._resourceName = self.name

        self.environment = project.get('environment') or {}
        self.source = project.get('source') or {}
        self.secondarySources = project.get('secondarySources') or []
        self.artifacts = project.get('artifacts') or {}
        self.logsConfig = project.get('logsConfig') or {}
        self.tags = project.get('_tags') or []

        self.addII('projectName', self.name)
        self.addII('region', project.get('_region', 'N/A'))
        self.addII('sourceType', self.source.get('type', 'N/A'))
        self.addII('environmentType', self.environment.get('type', 'N/A'))
        self.addII('image', self.environment.get('image', 'N/A'))
        self.addII('privilegedMode',
                   str(self.environment.get('privilegedMode', False)))
        self.addII('projectVisibility',
                   project.get('projectVisibility', 'N/A'))
        self.addII('serviceRole', project.get('serviceRole', 'N/A'))
        self.addII('vpcConfigured', str(bool(project.get('vpcConfig'))))
        self.addII('envVarCount',
                   str(len(self.environment.get('environmentVariables') or [])))
        self.addII('tagCount', str(len(self.tags)))

    # ------------------------------------------------------------------ #
    # 1. Plaintext credentials in environment variables  (FSBP CodeBuild.2)
    # ------------------------------------------------------------------ #
    def _checkCbPlaintextCredentialsInEnvVars(self):
        """
        Reports the variable NAME only. The value is deliberately never read
        into the finding: a build project's env vars are visible to anyone with
        codebuild:BatchGetProjects, and a scan report should not widen that.
        """
        envVars = self.environment.get('environmentVariables') or []
        if not envVars:
            self.results['cbPlaintextCredentialsInEnvVars'] = [
                0, f"Project '{self.name}' defines no environment variables"
            ]
            return

        offending = []
        for var in envVars:
            name = var.get('name') or ''
            varType = var.get('type') or 'PLAINTEXT'
            if varType in self.SECURE_ENV_TYPES:
                continue
            if self._nameLooksLikeCredential(name):
                offending.append(name)

        if offending:
            self.results['cbPlaintextCredentialsInEnvVars'] = [
                -1,
                "{} of {} environment variable(s) on project '{}' hold "
                "credential-shaped names as PLAINTEXT: {} — the values are "
                "readable by anyone with codebuild:BatchGetProjects and appear "
                "in build logs".format(
                    len(offending), len(envVars), self.name,
                    self._joinNames(offending))
            ]
        else:
            self.results['cbPlaintextCredentialsInEnvVars'] = [
                1,
                f"No credential-shaped PLAINTEXT environment variable on project "
                f"'{self.name}' ({len(envVars)} variable(s) checked)"
            ]

    # ------------------------------------------------------------------ #
    # 2. Credentials embedded in a source URL  (FSBP CodeBuild.1)
    # ------------------------------------------------------------------ #
    def _checkCbSourceUrlCredentials(self):
        """
        Reports WHICH source carries an inline credential, never the matched
        text. The regex looks for the userinfo form https://user:pass@host.
        """
        offending = []

        primary = self.source.get('location') or ''
        if self.URL_CREDENTIAL_PATTERN.search(primary):
            offending.append('primary source')

        for index, secondary in enumerate(self.secondarySources):
            location = (secondary or {}).get('location') or ''
            if self.URL_CREDENTIAL_PATTERN.search(location):
                identifier = (secondary or {}).get(
                    'sourceIdentifier') or f'secondary source {index}'
                offending.append(identifier)

        if offending:
            self.results['cbSourceUrlCredentials'] = [
                -1,
                "Project '{}' embeds credentials in the source URL of: {} — the "
                "credential is stored in the project definition in clear text "
                "and is logged on every clone".format(
                    self.name, self._joinNames(offending))
            ]
        else:
            self.results['cbSourceUrlCredentials'] = [
                1, f"No credentials embedded in any source URL of '{self.name}'"
            ]

    # ------------------------------------------------------------------ #
    # 3. Privileged mode
    # ------------------------------------------------------------------ #
    def _checkCbPrivilegedMode(self):
        """
        AWS retired the equivalent Security Hub control (CodeBuild.5) but
        privileged mode is still a genuine container-escape risk: it grants the
        build container full Docker daemon access, so a compromised dependency
        can reach the host and the instance credentials.
        """
        if self.environment.get('privilegedMode') is True:
            self.results['cbPrivilegedMode'] = [
                -1,
                f"Project '{self.name}' runs with privilegedMode=true — the "
                "build container has full Docker daemon access, so anything it "
                "executes can escape to the host and reach its credentials"
            ]
        else:
            self.results['cbPrivilegedMode'] = [
                1, f"Project '{self.name}' does not use privileged mode"
            ]

    # ------------------------------------------------------------------ #
    # 4. Public project visibility
    # ------------------------------------------------------------------ #
    def _checkCbProjectVisibilityPublic(self):
        ## The API enum is PUBLIC_READ / PRIVATE — not 'PUBLIC'.
        visibility = self.project.get('projectVisibility')
        if visibility == 'PUBLIC_READ':
            self.results['cbProjectVisibilityPublic'] = [
                -1,
                f"Project '{self.name}' has projectVisibility=PUBLIC_READ — its "
                "build logs, including any secret echoed during a build, are "
                "readable by anyone on the internet without authentication"
            ]
        elif visibility:
            self.results['cbProjectVisibilityPublic'] = [
                1, f"Project '{self.name}' visibility is {visibility}"
            ]
        else:
            self.results['cbProjectVisibilityPublic'] = [
                0, f"Project '{self.name}' does not report a visibility setting"
            ]

    # ------------------------------------------------------------------ #
    # 5. Artifact encryption disabled
    # ------------------------------------------------------------------ #
    def _checkCbNoArtifactEncryption(self):
        if not self.artifacts or self.artifacts.get('type') == 'NO_ARTIFACTS':
            self.results['cbNoArtifactEncryption'] = [
                0, f"Project '{self.name}' produces no artifacts"
            ]
            return

        if self.artifacts.get('encryptionDisabled') is True:
            self.results['cbNoArtifactEncryption'] = [
                -1,
                f"Project '{self.name}' has artifacts.encryptionDisabled=true — "
                "build output is written to S3 unencrypted, and build artifacts "
                "routinely contain source code and embedded configuration"
            ]
        else:
            self.results['cbNoArtifactEncryption'] = [
                1, f"Project '{self.name}' encrypts its build artifacts"
            ]

    # ------------------------------------------------------------------ #
    # 6. Default (AWS-managed) KMS key
    # ------------------------------------------------------------------ #
    def _checkCbEncryptionDefaultKey(self):
        """
        CodeBuild does not leave encryptionKey null when none is specified — it
        populates it with the AWS-managed alias/aws/s3 key. So the check is
        whether the key IS that default, not whether it is absent. Verified live:
        a project created with no --encryption-key reports
        arn:aws:kms:...:alias/aws/s3.
        """
        key = self.project.get('encryptionKey') or ''
        if not key:
            self.results['cbEncryptionDefaultKey'] = [
                0, f"Project '{self.name}' reports no encryption key"
            ]
        elif key.endswith('alias/aws/s3'):
            self.results['cbEncryptionDefaultKey'] = [
                -1,
                f"Project '{self.name}' encrypts build output with the AWS-managed "
                "key alias/aws/s3, whose policy the account cannot restrict, "
                "rotate or revoke — use a customer managed key"
            ]
        else:
            self.results['cbEncryptionDefaultKey'] = [
                1, f"Project '{self.name}' encrypts with the customer key {key}"
            ]

    # ------------------------------------------------------------------ #
    # 7. Insecure SSL on the source
    # ------------------------------------------------------------------ #
    def _checkCbInsecureSSL(self):
        if self.source.get('insecureSsl') is True:
            self.results['cbInsecureSSL'] = [
                -1,
                f"Project '{self.name}' has source.insecureSsl=true — TLS "
                "certificate validation is disabled when cloning, so the source "
                "can be substituted by anyone able to intercept the connection"
            ]
        else:
            self.results['cbInsecureSSL'] = [
                1, f"Project '{self.name}' validates TLS on source checkout"
            ]

    # ------------------------------------------------------------------ #
    # 8. No VPC configuration
    # ------------------------------------------------------------------ #
    def _checkCbNoVpcConfig(self):
        """
        INFO rather than FAIL. A build outside a VPC is the AWS default and is
        correct for most public-dependency builds; it only matters when the build
        needs private-subnet isolation or must reach private resources.
        """
        vpcConfig = self.project.get('vpcConfig') or {}
        if vpcConfig.get('vpcId'):
            self.results['cbNoVpcConfig'] = [
                1,
                f"Project '{self.name}' runs inside VPC {vpcConfig['vpcId']}"
            ]
        else:
            self.results['cbNoVpcConfig'] = [
                0,
                f"Project '{self.name}' is not attached to a VPC — builds have "
                "direct internet egress. Acceptable for public-dependency builds; "
                "review if the build handles sensitive data"
            ]

    # ------------------------------------------------------------------ #
    # 9. No build logging at all
    # ------------------------------------------------------------------ #
    def _checkCbLogsDisabled(self):
        cw = (self.logsConfig.get('cloudWatchLogs') or {})
        s3 = (self.logsConfig.get('s3Logs') or {})

        ## CodeBuild defaults CloudWatch logging to ENABLED, so an absent status
        ## is not 'off'. Only an explicit DISABLED counts.
        cwOff = cw.get('status') == 'DISABLED'
        s3Off = s3.get('status', 'DISABLED') == 'DISABLED'

        if cwOff and s3Off:
            self.results['cbLogsDisabled'] = [
                -1,
                f"Project '{self.name}' has both CloudWatch and S3 build logging "
                "disabled — there is no record of what any build did, so a "
                "compromised build cannot be investigated after the fact"
            ]
        else:
            destinations = []
            if not cwOff:
                destinations.append('CloudWatch Logs')
            if not s3Off:
                destinations.append('S3')
            self.results['cbLogsDisabled'] = [
                1,
                f"Project '{self.name}' logs builds to "
                + ' and '.join(destinations)
            ]

    # ------------------------------------------------------------------ #
    # 10. S3 build logs not encrypted
    # ------------------------------------------------------------------ #
    def _checkCbS3LogsNotEncrypted(self):
        s3 = self.logsConfig.get('s3Logs') or {}
        if s3.get('status') != 'ENABLED':
            self.results['cbS3LogsNotEncrypted'] = [
                0, f"Project '{self.name}' does not write build logs to S3"
            ]
            return

        if s3.get('encryptionDisabled') is True:
            self.results['cbS3LogsNotEncrypted'] = [
                -1,
                f"Project '{self.name}' writes S3 build logs with encryption "
                "disabled — build logs frequently contain resolved secrets, "
                "connection strings and internal hostnames"
            ]
        else:
            self.results['cbS3LogsNotEncrypted'] = [
                1, f"Project '{self.name}' encrypts its S3 build logs"
            ]

    # ------------------------------------------------------------------ #
    # 11. Unauthenticated public source
    # ------------------------------------------------------------------ #
    def _checkCbSourceCredentialsInsecure(self):
        sourceType = self.source.get('type')
        if sourceType not in ('GITHUB', 'GITHUB_ENTERPRISE', 'BITBUCKET'):
            self.results['cbSourceCredentialsInsecure'] = [
                0,
                f"Project '{self.name}' source type is {sourceType or 'unknown'} "
                "— third-party source authentication does not apply"
            ]
            return

        ## CodeBuild stores the OAuth/PAT token at the account level rather than
        ## per project, so an absent source.auth does NOT prove the source is
        ## unauthenticated. Report INFO and say why.
        if (self.source.get('auth') or {}).get('type'):
            self.results['cbSourceCredentialsInsecure'] = [
                1,
                f"Project '{self.name}' declares source authentication of type "
                + str(self.source['auth'].get('type'))
            ]
        else:
            self.results['cbSourceCredentialsInsecure'] = [
                0,
                f"Project '{self.name}' declares no per-project source auth. "
                "CodeBuild resolves credentials from the account-level source "
                "credential for the provider, so this is not conclusive — verify "
                "with list_source_credentials"
            ]

    # ------------------------------------------------------------------ #
    # 12. Deprecated build image
    # ------------------------------------------------------------------ #
    def _checkCbImageOutdated(self):
        image = self.environment.get('image') or ''
        if not image:
            self.results['cbImageOutdated'] = [
                0, f"Project '{self.name}' reports no build image"
            ]
            return

        lowered = image.lower()
        matched = [f for f in self.DEPRECATED_IMAGE_FRAGMENTS if f in lowered]
        if matched:
            self.results['cbImageOutdated'] = [
                -1,
                f"Project '{self.name}' builds on {image}, a retired CodeBuild "
                "image — its toolchain and OS packages no longer receive "
                "security updates"
            ]
        else:
            self.results['cbImageOutdated'] = [
                1, f"Project '{self.name}' uses build image {image}"
            ]

    # ------------------------------------------------------------------ #
    # 13. No concurrent build limit
    # ------------------------------------------------------------------ #
    def _checkCbConcurrentBuildLimitNotSet(self):
        limit = self.project.get('concurrentBuildLimit')
        if limit:
            self.results['cbConcurrentBuildLimitNotSet'] = [
                1, f"Project '{self.name}' caps concurrent builds at {limit}"
            ]
        else:
            self.results['cbConcurrentBuildLimitNotSet'] = [
                -1,
                f"Project '{self.name}' has no concurrentBuildLimit — a webhook "
                "loop or a push storm can start unbounded parallel builds, "
                "consuming the account's build minutes without a ceiling"
            ]

    # ------------------------------------------------------------------ #
    # 14. No tags
    # ------------------------------------------------------------------ #
    def _checkCbNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['cbNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['cbNoTags'] = [
                -1,
                f"Project '{self.name}' has no tags — it cannot be attributed to "
                "an owning team, and CI/CD projects accumulate faster than any "
                "other resource type"
            ]

    # ------------------------------------------------------------------ #
    # 15. Service role with administrator permissions  (SEC11-BP08)
    # ------------------------------------------------------------------ #
    def _checkCbServiceRoleOverprivileged(self):
        """
        A build executes whatever the source and its dependencies tell it to,
        so its service role is effectively granted to every contributor and
        every package the build pulls. FAIL when that role carries
        administrator or administrator-equivalent access: the AWS managed
        AdministratorAccess, PowerUserAccess or IAMFullAccess policy, or a
        customer managed / inline statement that Allows on Resource "*" either
        Action "*" / "*:*", Action "iam:*" (self-escalation), or any NotAction
        (PowerUser shape).

        The IamCommon evaluators (services/iam/drivers/IamCommon.py) are not
        reused: they write IAM-service result keys (FullAdminAccess,
        InlinePolicy, ...) onto the evaluator rather than returning a verdict,
        and do not cover NotAction.

        A permissions boundary caps the effective permissions; when the role
        has one that is not itself admin-shaped, report INFO instead of FAIL.
        Results are cached per role ARN because projects commonly share a role.
        """
        key = 'cbServiceRoleOverprivileged'
        roleArn = self.project.get('serviceRole') or ''
        if not roleArn:
            self.results[key] = [
                0, f"Project '{self.name}' reports no service role"]
            return
        if self.iamClient is None:
            self.results[key] = [0, 'Unable to evaluate (no IAM client)']
            return

        if roleArn not in self.roleCache:
            self.roleCache[roleArn] = self._evaluateServiceRole(roleArn)
        status, detail = self.roleCache[roleArn]
        self.results[key] = [status, f"Project '{self.name}': {detail}"]

    def _evaluateServiceRole(self, roleArn):
        ## arn:aws:iam::<acct>:role[/path]/<name> -- the name is the last segment.
        if roleArn.startswith('arn:'):
            if ':role/' not in roleArn:
                return [0, f"Service role '{roleArn}' is not an IAM role ARN"]
            roleAccount = roleArn.split(':')[4]
        else:
            ## CodeBuild also accepts a bare role name.
            roleAccount = None
        roleName = roleArn.rsplit('/', 1)[-1]

        try:
            role = self.iamClient.get_role(RoleName=roleName).get('Role') or {}
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            if code == 'NoSuchEntity':
                return [0, f"Service role '{roleName}' not found in this "
                           "account (deleted, or a cross-account role)"]
            return [0, f'Unable to evaluate ({code})']

        foundArn = role.get('Arn') or ''
        if roleAccount and foundArn.startswith('arn:') \
                and foundArn.split(':')[4] != roleAccount:
            ## Same name in a different account - not the role builds use.
            return [0, f"Service role '{roleArn}' is in another account - "
                       "not evaluable from this account"]

        try:
            adminSources = self._adminPolicySources(roleName)
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            return [0, f'Unable to evaluate ({code})']

        if not adminSources:
            return [1, f"service role '{roleName}' has no administrator-level "
                       "policy (AdministratorAccess/PowerUserAccess/"
                       "IAMFullAccess, or Allow *, iam:* or NotAction on *)"]

        boundary = (role.get('PermissionsBoundary') or {}).get(
            'PermissionsBoundaryArn')
        if boundary:
            try:
                boundaryAdmin = self._managedPolicyIsAdmin(boundary)
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', 'Unknown')
                return [0, f"service role '{roleName}' has administrator "
                           f"policies ({self._joinNames(adminSources)}) but its "
                           f"permissions boundary could not be read - Unable to "
                           f"evaluate ({code})"]
            if not boundaryAdmin:
                return [0, f"service role '{roleName}' has administrator "
                           f"policies ({self._joinNames(adminSources)}) capped "
                           f"by permissions boundary {boundary}; review that "
                           "the boundary is least privilege"]

        return [-1, f"service role '{roleName}' grants administrator or "
                    "administrator-equivalent access "
                    f"via {self._joinNames(adminSources)} - any code the build "
                    "runs (source, dependencies, buildspec) can do anything in "
                    "the account"]

    def _adminPolicySources(self, roleName):
        """Names of attached/inline policies on the role that grant admin."""
        sources = []

        paginator = self.iamClient.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=roleName):
            for policy in page.get('AttachedPolicies', []) or []:
                arn = policy.get('PolicyArn') or ''
                pname = policy.get('PolicyName') or arn.rsplit('/', 1)[-1]
                if self._isAwsManagedArn(arn):
                    ## AWS managed policies are matched by name (not fetched,
                    ## for cost): admin and admin-equivalent ones only.
                    if self._awsManagedIsAdmin(arn):
                        sources.append(f'{pname} (attached)')
                    continue
                if self._managedPolicyIsAdmin(arn):
                    sources.append(f'{pname} (attached)')

        paginator = self.iamClient.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=roleName):
            for pname in page.get('PolicyNames', []) or []:
                doc = self.iamClient.get_role_policy(
                    RoleName=roleName, PolicyName=pname).get('PolicyDocument')
                if self._documentIsAdmin(doc):
                    sources.append(f'{pname} (inline)')
        return sources

    @staticmethod
    def _isAwsManagedArn(arn):
        ## arn:<partition>:iam::aws:policy/...
        parts = arn.split(':')
        return len(parts) >= 6 and parts[4] == 'aws'

    ## AWS managed policies treated as administrator-equivalent:
    ##   AdministratorAccess -- Allow * on *
    ##   PowerUserAccess     -- Allow NotAction iam/organizations/account on *
    ##   IAMFullAccess       -- iam:* lets the role grant itself admin
    ADMIN_EQUIVALENT_AWS_POLICIES = frozenset([
        'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess'])

    @classmethod
    def _awsManagedIsAdmin(cls, arn):
        ## arn:<partition>:iam::aws:policy[/path]/<name>
        return arn.rsplit('/', 1)[-1] in cls.ADMIN_EQUIVALENT_AWS_POLICIES

    def _managedPolicyIsAdmin(self, policyArn):
        cacheKey = 'policy::' + policyArn
        if cacheKey in self.roleCache:
            return self.roleCache[cacheKey]
        if self._isAwsManagedArn(policyArn):
            result = self._awsManagedIsAdmin(policyArn)
        else:
            pol = self.iamClient.get_policy(PolicyArn=policyArn).get('Policy') or {}
            versionId = pol.get('DefaultVersionId')
            doc = None
            if versionId:
                doc = (self.iamClient.get_policy_version(
                    PolicyArn=policyArn, VersionId=versionId
                ).get('PolicyVersion') or {}).get('Document')
            result = self._documentIsAdmin(doc)
        self.roleCache[cacheKey] = result
        return result

    ## Actions that, granted on Resource "*", let a principal escalate to
    ## full administrator (attach/put any policy on itself, etc.).
    ESCALATION_WILDCARDS = frozenset(['iam:*'])

    @classmethod
    def _documentIsAdmin(cls, doc):
        """
        True when any Allow statement on Resource "*" grants:
          - Action "*" or "*:*" (administrator), or
          - NotAction ... (everything except the listed actions - e.g. the
            PowerUserAccess shape; admin-equivalent for a build role), or
          - Action "iam:*" (can grant itself administrator).
        Statements with NotResource or a narrower Resource are not counted;
        Conditions are not evaluated (a conditioned admin grant still FAILs).
        """
        if isinstance(doc, str):
            try:
                doc = json.loads(urllib.parse.unquote(doc))
            except ValueError:
                return False
        if not isinstance(doc, dict):
            return False
        statements = doc.get('Statement') or []
        if isinstance(statements, dict):
            statements = [statements]
        for st in statements:
            if not isinstance(st, dict) or st.get('Effect') != 'Allow':
                continue
            if 'NotResource' in st:
                continue
            resources = st.get('Resource')
            resources = resources if isinstance(resources, list) else [resources]
            if '*' not in resources:
                continue
            if 'NotAction' in st:
                return True
            actions = st.get('Action')
            if actions is None:
                continue
            actions = actions if isinstance(actions, list) else [actions]
            actions = [a.lower() for a in actions if isinstance(a, str)]
            if any(a in ('*', '*:*') for a in actions):
                return True
            if any(a in cls.ESCALATION_WILDCARDS for a in actions):
                return True
        return False

    # ------------------------------------------------------------------ #
    # 16. Webhook builds pull requests from any actor  (SEC11-BP08)
    # ------------------------------------------------------------------ #
    def _checkCbWebhookUnfiltered(self):
        """
        FAIL when the project has a webhook that will build un-merged pull
        request code from anyone:
          - filterGroups is empty (every event, including PRs, triggers), or
          - a filter group matches an unreviewed PULL_REQUEST_* event and has no
            ACTOR_ACCOUNT_ID include filter (excludeMatchedPattern false),
        unless pullRequestBuildPolicy.requiresCommentApproval gates PR builds
        behind collaborator approval AND no approverRoles entry is a
        read/triage-level role (those do not gate anything). A webhook whose
        status is CREATE_FAILED or DELETING does not trigger builds: INFO.

        Repository visibility is not observable through CodeBuild, so a private
        repository with only trusted collaborators is still reported; the
        message says so.
        """
        key = 'cbWebhookUnfiltered'
        webhook = self.project.get('webhook') or {}
        if not webhook:
            self.results[key] = [
                0, f"Project '{self.name}' has no source webhook"]
            return

        status = webhook.get('status')
        if status in self.WEBHOOK_INACTIVE:
            self.results[key] = [
                0,
                f"Project '{self.name}' webhook is {status} and does not "
                "trigger builds"
                + (f" ({webhook.get('statusMessage')})"
                   if webhook.get('statusMessage') else "")]
            return

        policy = webhook.get('pullRequestBuildPolicy') or {}
        approval = policy.get('requiresCommentApproval')
        approvers = [r for r in (policy.get('approverRoles') or []) if r]
        weakApprovers = sorted(set(approvers) & self.LOW_TRUST_APPROVER_ROLES)
        if approval in self.PR_APPROVAL_GATED and not weakApprovers:
            approverText = (', '.join(approvers) if approvers
                            else 'default write-level-and-above roles')
            self.results[key] = [
                1,
                f"Project '{self.name}' webhook requires comment approval for "
                f"pull request builds ({approval}; approvers: {approverText})"]
            return
        ## Approval by read/triage-level users is not a meaningful gate: anyone
        ## who can read the repository (any GitHub user for a public repo) can
        ## approve. Fall through to the actor-filter evaluation.
        weakNote = ''
        if approval in self.PR_APPROVAL_GATED and weakApprovers:
            weakNote = (f" Comment approval ({approval}) is configured but "
                        f"low-trust roles can approve ({', '.join(weakApprovers)}),"
                        " so it does not gate builds.")

        groups = webhook.get('filterGroups') or []
        if not groups:
            self.results[key] = [
                -1,
                f"Project '{self.name}' webhook has no filter groups, so every "
                "event - including pull requests from any contributor or fork "
                "- starts a build with the project's service role. (Repository "
                "visibility is not visible to this check; lower risk if the "
                "repository is private and collaborators are trusted.)"
                + weakNote]
            return

        offending = []
        for index, group in enumerate(groups):
            filters = [f for f in (group or []) if isinstance(f, dict)]
            if not self._groupMatchesUnreviewedPr(filters):
                continue
            hasActor = any(
                (f.get('type') == 'ACTOR_ACCOUNT_ID'
                 and not f.get('excludeMatchedPattern')
                 and (f.get('pattern') or '').strip())
                for f in filters)
            if not hasActor:
                offending.append(f'filter group {index + 1}')

        if offending:
            self.results[key] = [
                -1,
                f"Project '{self.name}' webhook builds pull requests without an "
                f"ACTOR_ACCOUNT_ID filter in {self._joinNames(offending)} - "
                "un-reviewed code from any contributor or fork runs with the "
                "project's service role. (Repository visibility is not visible "
                "to this check; lower risk if the repository is private.)"
                + weakNote]
        else:
            self.results[key] = [
                1,
                f"Project '{self.name}' webhook restricts pull request builds "
                f"to allowed actors ({len(groups)} filter group(s) checked)"]

    def _groupMatchesUnreviewedPr(self, filters):
        events = [f for f in filters if f.get('type') == 'EVENT']
        if not events:
            ## A group without an EVENT filter matches every event.
            return True
        for f in events:
            listed = {e.strip().upper()
                      for e in (f.get('pattern') or '').split(',') if e.strip()}
            if f.get('excludeMatchedPattern'):
                ## Everything EXCEPT the listed events.
                if self.UNREVIEWED_PR_EVENTS - listed:
                    return True
            elif listed & self.UNREVIEWED_PR_EVENTS:
                return True
        return False

    # ------------------------------------------------------------------ #
    # 17. No test reports  (SEC11-BP03, tier 3 heuristic)
    # ------------------------------------------------------------------ #
    def _checkCbProjectNoTestReports(self):
        """
        Evidence that the project publishes test / code-coverage reports:
          a. its inline buildspec (YAML or JSON, e.g. CDK BuildSpec.fromObject)
             has a non-empty top-level 'reports' section; or
          b. a recent report in any report group was produced by this
             project (report.executionId names the project); or
          c. a report group named '<project>-<name>' exists (the name CodeBuild
             gives auto-created report groups), attributed to the project with
             the LONGEST matching name so 'app' does not claim 'app-api-tests'
             that belongs to project 'app-api'.

        Outcomes:
          - inline buildspec structurally parsed and has no reports section:
            FAIL (the buildspec is authoritative for which reports a build
            publishes; b/c are still checked first in case reports are
            supplied by a buildspec override);
          - buildspec in the source repository, or an inline buildspec that
            could not be parsed: FAIL only when b/c are fully readable and find
            nothing; 'Unable to evaluate' when report data cannot be read.

        Heuristic limits (tier 3, criticality L): only the 25 newest reports
        per group are sampled for (b); a prefix-named group (c) is attributed
        by name only.
        """
        key = 'cbProjectNoTestReports'
        buildspec = (self.source.get('buildspec') or '')
        state = self._buildspecReportsState(buildspec)

        if state == 'reports':
            self.results[key] = [
                1, f"Project '{self.name}' buildspec defines a reports section"]
            return

        index = self.reportIndexFn() if self.reportIndexFn else None
        if index and not index.get('listError'):
            if self.name in index.get('projects', set()):
                self.results[key] = [
                    1, f"Project '{self.name}' has published test reports"]
                return
            knownProjects = set(index.get('projectNames') or []) | {self.name}
            ownGroups = [g for g in index.get('groupNames', [])
                         if self._groupOwner(g, knownProjects) == self.name]
            if ownGroups:
                self.results[key] = [
                    1, f"Project '{self.name}' has a report group "
                       f"({self._joinNames(ownGroups)})"]
                return

        if state == 'noreports':
            self.results[key] = [
                -1,
                f"Project '{self.name}' inline buildspec has no reports section "
                "- test and coverage results are not published to CodeBuild "
                "report groups"]
            return

        if index is None:
            self.results[key] = [0, 'Unable to evaluate (no report data)']
            return
        err = index.get('listError') or index.get('linkageError')
        if err:
            self.results[key] = [0, f'Unable to evaluate ({err})']
            return

        self.results[key] = [
            -1,
            f"Project '{self.name}' has not published any test or coverage "
            "report to a CodeBuild report group"
            + (" (inline buildspec could not be parsed)"
               if state == 'unknown' else "")]

    ## Top-level key line in a block-style YAML buildspec: optional quotes.
    _YAML_TOP_KEY = re.compile(
        r"""^(?P<indent>[ ]*)(?P<q>["']?)(?P<key>[A-Za-z0-9_-]+)(?P=q)\s*:""")

    def _buildspecReportsState(self, buildspec):
        """
        Classify the project's buildspec field without a YAML library:
          'path'      -- not inline (empty, a file path, or an S3 ARN)
          'reports'   -- inline, with a non-empty top-level reports section
          'noreports' -- inline, structurally parsed, no reports section
          'unknown'   -- looks inline but could not be parsed reliably
        """
        text = buildspec.strip()
        if not text:
            return 'path'

        if text.startswith('{'):
            ## JSON (CDK BuildSpec.fromObject) - or YAML flow style.
            try:
                doc = json.loads(text)
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                return 'reports' if doc.get('reports') else 'noreports'
            ## YAML flow mapping: look for a reports key; cannot be sure it is
            ## top level, so absence is inconclusive.
            if re.search(r"""[{,]\s*["']?reports["']?\s*:""", text):
                return 'reports'
            return 'unknown'

        if '\n' not in text:
            ## A single line that is not a mapping is a path / S3 ARN. A
            ## single-line 'key: value' YAML is inline but cannot hold phases.
            if re.match(r"""^["']?[A-Za-z0-9_-]+["']?\s*:\s""", text):
                return 'noreports'
            return 'path'

        ## Block-style YAML. Top-level keys share the indentation of the first
        ## key line (normally column 0).
        topIndent = None
        topKeys = {}
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped == '---':
                continue
            m = self._YAML_TOP_KEY.match(line)
            if topIndent is None:
                if not m:
                    return 'unknown'
                topIndent = len(m.group('indent'))
            if m and len(m.group('indent')) == topIndent:
                k = m.group('key')
                rest = line[m.end():].split('#', 1)[0].strip()
                topKeys[k] = (i, rest)
        if not topKeys or not ({'version', 'phases'} & set(topKeys)):
            return 'unknown'
        if 'reports' not in topKeys:
            return 'noreports'

        ## Non-empty: an inline value, or at least one more-indented line next.
        i, rest = topKeys['reports']
        if rest and rest not in ('~', 'null', '{}', 'Null', 'NULL'):
            return 'reports'
        for line in lines[i + 1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            indent = len(line) - len(line.lstrip(' '))
            return 'reports' if indent > topIndent else 'noreports'
        return 'noreports'

    @staticmethod
    def _groupOwner(groupName, projectNames):
        """Project an auto-named '<project>-<x>' report group belongs to: the
        longest project name that prefixes it."""
        best = None
        for p in projectNames:
            if groupName.startswith(p + '-') and (best is None
                                                  or len(p) > len(best)):
                best = p
        return best

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _nameLooksLikeCredential(self, name):
        lowered = (name or '').lower()
        if lowered in self.EXACT_CREDENTIAL_NAMES:
            return True
        return any(f in lowered for f in self.CREDENTIAL_NAME_FRAGMENTS)

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
