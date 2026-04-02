import json

# Define sensitive actions that should have security conditions
SENSITIVE_ACTIONS = {
    'iam_modifications': [
        'iam:CreateUser',
        'iam:CreateRole',
        'iam:AttachUserPolicy',
        'iam:AttachRolePolicy',
        'iam:PutUserPolicy',
        'iam:PutRolePolicy',
        'iam:CreateAccessKey',
        'iam:UpdateAccessKey'
    ],
    'security_config': [
        'iam:DeleteAccountPasswordPolicy',
        'iam:UpdateAccountPasswordPolicy',
        'kms:ScheduleKeyDeletion',
        'kms:DisableKey',
        's3:PutBucketPolicy',
        's3:DeleteBucketPolicy'
    ],
    'privilege_escalation': [
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:PassRole',
        'sts:AssumeRole'
    ]
}

# Flatten all sensitive actions into a single list for easy lookup
ALL_SENSITIVE_ACTIONS = []
for category in SENSITIVE_ACTIONS.values():
    ALL_SENSITIVE_ACTIONS.extend(category)

# Define security condition types and their AWS condition keys
SECURITY_CONDITIONS = {
    'mfa': ['aws:MultiFactorAuthPresent', 'aws:MultiFactorAuthAge'],
    'ip_restriction': ['aws:SourceIp', 'aws:VpcSourceIp'],
    'secure_transport': ['aws:SecureTransport']
}

# Define SCP best practice patterns
SCP_PATTERNS = {
    'deny_root': {
        'description': 'Deny root user actions',
        'effect': 'Deny',
        'principal_patterns': ['arn:aws:iam::*:root', '*'],
        'condition_keys': ['aws:PrincipalArn']
    },
    'restrict_regions': {
        'description': 'Restrict access to specific regions',
        'effect': 'Deny',
        'condition_keys': ['aws:RequestedRegion']
    },
    'prevent_priv_escalation': {
        'description': 'Prevent privilege escalation through IAM actions',
        'effect': 'Deny',
        'actions': [
            'iam:CreatePolicyVersion',
            'iam:SetDefaultPolicyVersion',
            'iam:AttachUserPolicy',
            'iam:AttachRolePolicy',
            'iam:PutUserPolicy',
            'iam:PutRolePolicy',
            'iam:CreateAccessKey',
            'iam:CreateLoginProfile',
            'iam:UpdateLoginProfile',
            'iam:PassRole'
        ]
    }
}

class Policy:
    fullAccessList = {
        'oneService': False,
        'fullAdmin': False
    }
    
    publicAccess = False
    wildcardActions = []
    
    def __init__(self, document):
        self.fullAccessList = {
            'oneService': False,
            'fullAdmin': False
        }
        self.wildcardActions = []
        self.conditions = {}  # Maps statement index to condition blocks
        self.scpValidation = {}  # Stores SCP validation results
        
        self.doc = document
        # self.doc = json.loads(document)
        
    ## Only if it is a string objects, some boto3 api does not return as array
    def parseDocumentToJson(self):
        self.doc = json.loads(self.doc)
    
    def inspectAccess(self):
        doc = self.doc
        docState = doc['Statement']
        if type(doc['Statement']).__name__ == 'dict':
            docState = [doc['Statement']]
        for statement in docState:
            if statement['Effect'] != 'Allow':
                continue
                
            if 'Action' in statement:    
                actions = statement['Action']
                actions = actions if isinstance(actions, list) else [actions]
            
                for action in actions:
                    perm = action.split(':')
                    
                    if len(perm) != 1:
                        serv, perm = perm
                    else:
                        serv = perm = '*'
                        
                    if perm == '*' and serv == '*':
                        self.fullAccessList['fullAdmin'] = True
                        return
                    
                    if perm == '*':
                        self.fullAccessList['oneService'] = True
                        # Track service-level wildcards (but not full admin)
                        if serv != '*':
                            self.wildcardActions.append(f"{serv}:*")
            
            elif 'NotAction' in statement:
                self.fullAccessList['oneService'] = True
                    
        return False
    
    def hasWildcardActions(self):
        """Check if policy has service-level wildcard actions (e.g., s3:*, ec2:*)"""
        return len(self.wildcardActions) > 0
    
    def getWildcardActions(self):
        """Return list of wildcard actions found"""
        return self.wildcardActions
        
    def hasFullAccessToOneResource(self):
        return self.fullAccessList['oneService']
    
    def hasFullAccessAdmin(self):
        return self.fullAccessList['fullAdmin']
        
    def inspectPrinciple(self):
        doc = self.doc
        for statement in doc['Statement']:
            if statement['Effect'] != 'Allow':
                continue
            
            principals = statement['Principal']
            principals = principals if isinstance(principals, list) else [principals]
            
            for principal in principals:
                if principal == '*':
                    self.publicAccess = True
                    return
                
        return False
    
    def hasPublicAccess(self):
        return self.publicAccess

    def extractPolicyInfo(self):
        doc = self.doc
        
        policy = {'allow': {}, 'deny': {}}
        cnt = 1;
        for statement in doc['Statement']:
            effect = statement['Effect'].lower()
            
            if 'Sid' in statement:
                sid = statement['Sid']
            else:
                sid = 'noSid:' + str(cnt)
                cnt = cnt + 1
            
            policy[effect][sid] = {'Principal': statement['Principal'], 'Action': statement['Action']}
            
        return policy

    def parseConditions(self):
        """
        Extract and parse Condition blocks from policy statements.
        Returns dict mapping statement index to condition data.
        """
        doc = self.doc
        docState = doc.get('Statement', [])
        
        # Handle case where Statement is a dict instead of list
        if type(docState).__name__ == 'dict':
            docState = [docState]
        
        self.conditions = {}
        
        for idx, statement in enumerate(docState):
            if 'Condition' in statement:
                self.conditions[idx] = statement['Condition']
        
        return self.conditions

    def hasSecurityConditions(self, action):
        """
        Check if policy has security conditions for given action.
        Returns dict with keys: hasMFA, hasIpRestriction, hasSecureTransport
        """
        result = {
            'hasMFA': False,
            'hasIpRestriction': False,
            'hasSecureTransport': False
        }
        
        # Parse conditions if not already done
        if not self.conditions:
            self.parseConditions()
        
        doc = self.doc
        docState = doc.get('Statement', [])
        
        # Handle case where Statement is a dict instead of list
        if type(docState).__name__ == 'dict':
            docState = [docState]
        
        # Check each statement for the action and its conditions
        for idx, statement in enumerate(docState):
            if statement.get('Effect') != 'Allow':
                continue
            
            # Get actions from statement
            actions = statement.get('Action', [])
            actions = actions if isinstance(actions, list) else [actions]
            
            # Check if this statement contains the action we're looking for
            action_found = False
            for stmt_action in actions:
                if stmt_action == action or stmt_action == '*':
                    action_found = True
                    break
            
            if not action_found:
                continue
            
            # Check if this statement has conditions
            if idx in self.conditions:
                conditions = self.conditions[idx]
                
                # Check for MFA conditions
                for mfa_key in SECURITY_CONDITIONS['mfa']:
                    if mfa_key in str(conditions):
                        result['hasMFA'] = True
                
                # Check for IP restriction conditions
                for ip_key in SECURITY_CONDITIONS['ip_restriction']:
                    if ip_key in str(conditions):
                        result['hasIpRestriction'] = True
                
                # Check for secure transport conditions
                for secure_key in SECURITY_CONDITIONS['secure_transport']:
                    if secure_key in str(conditions):
                        result['hasSecureTransport'] = True
        
        return result
    
    def getMissingConditions(self, sensitive_actions):
        """
        Identify sensitive actions missing security conditions.
        Returns list of dicts with action and missing condition types.
        """
        missing = []
        
        doc = self.doc
        docState = doc.get('Statement', [])
        
        # Handle case where Statement is a dict instead of list
        if type(docState).__name__ == 'dict':
            docState = [docState]
        
        # Parse conditions if not already done
        if not self.conditions:
            self.parseConditions()
        
        # Track which sensitive actions are in the policy
        actions_in_policy = set()
        
        for statement in docState:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            actions = actions if isinstance(actions, list) else [actions]
            
            for action in actions:
                # Check if this is a sensitive action
                if action in sensitive_actions or action in ALL_SENSITIVE_ACTIONS:
                    actions_in_policy.add(action)
                # Also check for wildcard patterns
                elif '*' in action:
                    # e.g., "iam:*" matches all iam actions
                    service_prefix = action.split(':')[0] if ':' in action else ''
                    for sensitive_action in sensitive_actions:
                        if sensitive_action.startswith(service_prefix + ':'):
                            actions_in_policy.add(sensitive_action)
        
        # For each sensitive action found, check what conditions are missing
        for action in actions_in_policy:
            conditions_check = self.hasSecurityConditions(action)
            
            missing_types = []
            if not conditions_check['hasMFA']:
                missing_types.append('MFA')
            if not conditions_check['hasIpRestriction']:
                missing_types.append('IP restriction')
            if not conditions_check['hasSecureTransport']:
                missing_types.append('SecureTransport')
            
            # Only report if at least one condition type is missing
            if missing_types:
                missing.append({
                    'action': action,
                    'missing': missing_types
                })
        
        return missing

    def validateScpBestPractices(self):
        """
        Validate SCP document against best practice patterns.
        Returns dict with keys: denyRoot, restrictRegions, preventPrivEscalation
        Each key contains a boolean indicating if the pattern is present.
        """
        self.scpValidation = {
            'denyRoot': False,
            'restrictRegions': False,
            'preventPrivEscalation': False
        }
        
        doc = self.doc
        docState = doc.get('Statement', [])
        
        # Handle case where Statement is a dict instead of list
        if type(docState).__name__ == 'dict':
            docState = [docState]
        
        for statement in docState:
            # Only check Deny statements for SCP best practices
            if statement.get('Effect') != 'Deny':
                continue
            
            # Check for root user denial pattern
            if not self.scpValidation['denyRoot']:
                self.scpValidation['denyRoot'] = self._checkRootDenial(statement)
            
            # Check for region restriction pattern
            if not self.scpValidation['restrictRegions']:
                self.scpValidation['restrictRegions'] = self._checkRegionRestriction(statement)
            
            # Check for privilege escalation prevention pattern
            if not self.scpValidation['preventPrivEscalation']:
                self.scpValidation['preventPrivEscalation'] = self._checkPrivilegeEscalationPrevention(statement)
        
        return self.scpValidation
    
    def _checkRootDenial(self, statement):
        """
        Check if statement denies root user actions.
        Looks for conditions targeting root principal ARN.
        """
        condition = statement.get('Condition', {})
        
        # Check for StringLike or StringEquals conditions on aws:PrincipalArn
        for condition_operator in ['StringLike', 'StringEquals']:
            if condition_operator in condition:
                principal_conditions = condition[condition_operator]
                if 'aws:PrincipalArn' in principal_conditions:
                    principal_values = principal_conditions['aws:PrincipalArn']
                    principal_values = principal_values if isinstance(principal_values, list) else [principal_values]
                    
                    # Check if any value matches root user pattern
                    for value in principal_values:
                        if 'arn:aws:iam::*:root' in value or value.endswith(':root'):
                            return True
        
        return False
    
    def _checkRegionRestriction(self, statement):
        """
        Check if statement restricts access to specific regions.
        Looks for conditions on aws:RequestedRegion.
        """
        condition = statement.get('Condition', {})
        
        # Check for StringNotEquals or StringNotLike conditions on aws:RequestedRegion
        for condition_operator in ['StringNotEquals', 'StringNotLike', 'StringNotEqualsIfExists']:
            if condition_operator in condition:
                if 'aws:RequestedRegion' in condition[condition_operator]:
                    return True
        
        return False
    
    def _checkPrivilegeEscalationPrevention(self, statement):
        """
        Check if statement prevents privilege escalation through IAM actions.
        Looks for denials of sensitive IAM actions.
        """
        actions = statement.get('Action', [])
        actions = actions if isinstance(actions, list) else [actions]
        
        # Get the list of privilege escalation actions from SCP_PATTERNS
        priv_esc_actions = SCP_PATTERNS['prevent_priv_escalation']['actions']
        
        # Check if any of the denied actions match privilege escalation patterns
        for action in actions:
            # Check for exact matches
            if action in priv_esc_actions:
                return True
            
            # Check for wildcard patterns like "iam:*"
            if '*' in action:
                service_prefix = action.split(':')[0] if ':' in action else ''
                for priv_action in priv_esc_actions:
                    if priv_action.startswith(service_prefix + ':'):
                        return True
        
        return False
