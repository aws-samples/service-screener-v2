import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2Regional(Evaluator):
    """Regional-level EC2 checks (not resource-specific)"""
    
    def __init__(self, ec2Client, compOptClient=None, rbinClient=None):
        super().__init__()
        self.ec2Client = ec2Client
        self.compOptClient = compOptClient
        self.rbinClient = rbinClient
        
        self._resourceName = f"EC2-Regional-{ec2Client.meta.region_name}"
        
        self.init()
    
    def _checkEBSEncryptionByDefault(self):
        """Check if EBS encryption by default is enabled in this region"""
        try:
            resp = self.ec2Client.get_ebs_encryption_by_default()
            
            encryptionEnabled = resp.get('EbsEncryptionByDefault', False)
            
            if not encryptionEnabled:
                self.results['EBSEncryptionByDefault'] = [-1, 'Disabled']
        
        except Exception as e:
            # If API not available, skip check
            return
    
    def _checkEC2ServiceQuotas(self):
        """Check if EC2 service quotas are approaching limits"""
        try:
            # Get account attributes which include some quotas
            resp = self.ec2Client.describe_account_attributes()
            
            attributes = resp.get('AccountAttributes', [])
            
            # Get current resource counts
            instancesResp = self.ec2Client.describe_instances()
            instanceCount = 0
            for reservation in instancesResp.get('Reservations', []):
                instanceCount += len(reservation.get('Instances', []))
            
            volumesResp = self.ec2Client.describe_volumes()
            volumeCount = len(volumesResp.get('Volumes', []))
            
            snapshotsResp = self.ec2Client.describe_snapshots(OwnerIds=['self'])
            snapshotCount = len(snapshotsResp.get('Snapshots', []))
            
            # Check against limits
            quotasApproachingLimit = []
            
            for attr in attributes:
                attrName = attr.get('AttributeName')
                attrValues = attr.get('AttributeValues', [])
                
                if not attrValues:
                    continue
                
                limitValue = attrValues[0].get('AttributeValue')
                
                try:
                    limit = int(limitValue)
                except (ValueError, TypeError):
                    continue
                
                # Check specific quotas
                if attrName == 'max-instances':
                    utilization = (instanceCount / limit) * 100 if limit > 0 else 0
                    if utilization > 80:
                        quotasApproachingLimit.append(f"Instances: {instanceCount}/{limit} ({utilization:.0f}%)")
                
                elif attrName == 'max-elastic-ips':
                    eipsResp = self.ec2Client.describe_addresses()
                    eipCount = len(eipsResp.get('Addresses', []))
                    utilization = (eipCount / limit) * 100 if limit > 0 else 0
                    if utilization > 80:
                        quotasApproachingLimit.append(f"Elastic IPs: {eipCount}/{limit} ({utilization:.0f}%)")
            
            # Note: Volume and snapshot limits are typically very high and not returned by describe_account_attributes
            # We'll flag if counts are unusually high (>1000 for volumes, >10000 for snapshots)
            if volumeCount > 1000:
                quotasApproachingLimit.append(f"Volumes: {volumeCount} (consider reviewing)")
            
            if snapshotCount > 10000:
                quotasApproachingLimit.append(f"Snapshots: {snapshotCount} (consider reviewing)")
            
            if quotasApproachingLimit:
                self.results['EC2ServiceQuotas'] = [-1, ', '.join(quotasApproachingLimit)]
        
        except Exception as e:
            # If we can't check quotas, skip
            return

    def _checkComputeOptimizerEnhancedMetrics(self):
        """Check if Compute Optimizer enhanced infrastructure metrics are enabled"""
        if not self.compOptClient:
            return
        try:
            resp = self.compOptClient.get_enrollment_status()
            status = resp.get('status', '')
            if status != 'Active':
                return  # Compute Optimizer not active, skip this check

            # Check recommendation preferences for enhanced metrics
            try:
                prefsResp = self.compOptClient.get_recommendation_preferences(
                    resourceType='Ec2Instance'
                )
                preferences = prefsResp.get('recommendationPreferencesDetails', [])

                enhancedMetricsEnabled = False
                for pref in preferences:
                    if pref.get('enhancedInfrastructureMetrics') == 'Active':
                        enhancedMetricsEnabled = True
                        break

                if not enhancedMetricsEnabled:
                    self.results['ComputeOptimizerEnhancedMetrics'] = [-1, 'Not enabled']
            except Exception:
                # If we can't check preferences, flag as not enabled
                self.results['ComputeOptimizerEnhancedMetrics'] = [-1, 'Unable to verify']
        except Exception:
            return

    def _checkComputeOptimizerRightsizingPrefs(self):
        """Check if Compute Optimizer rightsizing preferences are customized"""
        if not self.compOptClient:
            return
        try:
            resp = self.compOptClient.get_enrollment_status()
            status = resp.get('status', '')
            if status != 'Active':
                return  # Compute Optimizer not active, skip

            # Check recommendation preferences
            try:
                prefsResp = self.compOptClient.get_recommendation_preferences(
                    resourceType='Ec2Instance'
                )
                preferences = prefsResp.get('recommendationPreferencesDetails', [])

                # Check if any preferences have been customized (lookBackPeriod set)
                hasCustomPrefs = False
                for pref in preferences:
                    if pref.get('lookBackPeriod') and pref.get('lookBackPeriod') != 'DAYS_14':
                        hasCustomPrefs = True
                        break

                if not hasCustomPrefs:
                    self.results['ComputeOptimizerRightsizingPrefs'] = [-1, 'Default preferences']
            except Exception:
                self.results['ComputeOptimizerRightsizingPrefs'] = [-1, 'Unable to verify']
        except Exception:
            return

    def _checkComputeOptimizerExportRecommendations(self):
        """Check if Compute Optimizer recommendation export is configured"""
        if not self.compOptClient:
            return
        try:
            resp = self.compOptClient.get_enrollment_status()
            status = resp.get('status', '')
            if status != 'Active':
                return  # Compute Optimizer not active, skip

            # Check for export jobs
            try:
                exportResp = self.compOptClient.describe_recommendation_export_jobs()
                exportJobs = exportResp.get('recommendationExportJobs', [])

                if not exportJobs:
                    self.results['ComputeOptimizerExportRecommendations'] = [-1, 'No export jobs']
            except Exception:
                self.results['ComputeOptimizerExportRecommendations'] = [-1, 'Unable to verify']
        except Exception:
            return

    # ------------------------------------------------------------------ #
    # WAFS2027 account/region-level preventive controls
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(e):
        if isinstance(e, botocore.exceptions.ClientError):
            return e.response.get('Error', {}).get('Code', 'ClientError')
        return type(e).__name__

    def _checkEc2ImageBlockPublicAccessOff(self):
        """AMI Block Public Access must be 'block-new-sharing' (the only blocking state)."""
        key = 'ec2ImageBlockPublicAccessOff'
        try:
            resp = self.ec2Client.get_image_block_public_access_state()
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return

        state = resp.get('ImageBlockPublicAccessState')
        managedBy = resp.get('ManagedBy')
        suffix = f" (managed by {managedBy})" if managedBy else ''
        if state == 'block-new-sharing':
            self.results[key] = [1, f"block-new-sharing{suffix}"]
        elif state == 'unblocked':
            self.results[key] = [-1, f"unblocked{suffix}"]
        else:
            self.results[key] = [0, f"Unable to evaluate (unknown state: {state})"]

    def _checkEc2ImdsDefaultNotRequired(self):
        """Account-level IMDS defaults for new launches should require IMDSv2
        (HttpTokens=required) with a hop limit no greater than 2."""
        key = 'ec2ImdsDefaultNotRequired'
        try:
            resp = self.ec2Client.get_instance_metadata_defaults()
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return

        acct = resp.get('AccountLevel') or {}
        tokens = acct.get('HttpTokens')
        endpoint = acct.get('HttpEndpoint')
        hopLimit = acct.get('HttpPutResponseHopLimit')

        if endpoint == 'disabled':
            self.results[key] = [1, 'Instance metadata endpoint disabled by default']
            return

        issues = []
        if tokens != 'required':
            issues.append(f"HttpTokens={tokens if tokens else 'not set (IMDSv1 allowed unless AMI/launch requires IMDSv2)'}")
        if isinstance(hopLimit, int) and hopLimit > 2:
            issues.append(f"HttpPutResponseHopLimit={hopLimit} (>2)")

        if issues:
            self.results[key] = [-1, '; '.join(issues)]
        else:
            self.results[key] = [1, f"HttpTokens=required{', HttpPutResponseHopLimit=' + str(hopLimit) if hopLimit else ''}"]

    def _checkEc2SnapshotBlockPublicAccessOff(self):
        """EBS snapshot Block Public Access should be 'block-all-sharing'.
        'block-new-sharing' is reported as INFO: existing public snapshots stay
        public (those are reported by EBSSnapshotIsPublic)."""
        key = 'ec2SnapshotBlockPublicAccessOff'
        try:
            resp = self.ec2Client.get_snapshot_block_public_access_state()
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return

        state = resp.get('State')
        managedBy = resp.get('ManagedBy')
        suffix = f" (managed by {managedBy})" if managedBy else ''
        if state == 'block-all-sharing':
            self.results[key] = [1, f"block-all-sharing{suffix}"]
        elif state == 'block-new-sharing':
            self.results[key] = [0, f"block-new-sharing{suffix}: new public sharing is blocked but existing public snapshots remain public; consider block-all-sharing"]
        elif state == 'unblocked':
            self.results[key] = [-1, f"unblocked{suffix}"]
        else:
            self.results[key] = [0, f"Unable to evaluate (unknown state: {state})"]

    def _hasSelfOwned(self, kind):
        if kind == 'EBS_SNAPSHOT':
            resp = self.ec2Client.describe_snapshots(OwnerIds=['self'], MaxResults=5)
            return len(resp.get('Snapshots', [])) > 0
        resp = self.ec2Client.describe_images(Owners=['self'], MaxResults=5)
        return len(resp.get('Images', [])) > 0

    def _checkEbsRecycleBinMissing(self):
        """Recycle Bin retention rules protect EBS snapshots / AMIs from
        accidental or malicious deletion. A resource type is required only when
        the region holds self-owned resources of that type.
          FAIL  - no Recycle Bin rule for a required type
          INFO  - rules exist but only tag-level, or the region-level rule is not locked
          PASS  - a locked region-level rule exists for every required type"""
        key = 'ebsRecycleBinMissing'
        if self.rbinClient is None:
            self.results[key] = [0, 'Unable to evaluate (rbin client unavailable)']
            return

        try:
            required = [k for k in ('EBS_SNAPSHOT', 'EC2_IMAGE') if self._hasSelfOwned(k)]
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return

        if not required:
            self.results[key] = [1, 'No self-owned EBS snapshots or AMIs in this region']
            return

        missing, warns, ok = [], [], []
        try:
            for rtype in required:
                rules = []
                paginator = self.rbinClient.get_paginator('list_rules')
                for page in paginator.paginate(ResourceType=rtype):
                    rules.extend(page.get('Rules', []))

                if not rules:
                    missing.append(rtype)
                    continue

                regionLocked = regionUnlocked = tagLevel = 0
                for summary in rules:
                    detail = self.rbinClient.get_rule(Identifier=summary['Identifier'])
                    lockState = detail.get('LockState') or summary.get('LockState')
                    if detail.get('ResourceTags'):
                        tagLevel += 1
                    elif lockState == 'locked':
                        regionLocked += 1
                    else:
                        regionUnlocked += 1

                if regionLocked:
                    ok.append(rtype)
                elif regionUnlocked:
                    warns.append(f"{rtype}: region-level rule not locked")
                else:
                    warns.append(f"{rtype}: only tag-level rule(s) ({tagLevel}); untagged resources are not protected")
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return

        if missing:
            msg = 'No Recycle Bin rule for: ' + ', '.join(missing)
            if warns:
                msg += '; ' + '; '.join(warns)
            self.results[key] = [-1, msg]
        elif warns:
            self.results[key] = [0, '; '.join(warns)]
        else:
            self.results[key] = [1, 'Locked region-level Recycle Bin rule for: ' + ', '.join(ok)]
