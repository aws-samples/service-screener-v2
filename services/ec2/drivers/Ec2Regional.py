import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2Regional(Evaluator):
    """Regional-level EC2 checks (not resource-specific)"""
    
    def __init__(self, ec2Client, compOptClient=None):
        super().__init__()
        self.ec2Client = ec2Client
        self.compOptClient = compOptClient
        
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



