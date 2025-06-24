import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2AutoScaling(Evaluator):
    def __init__(self, asg, asgClient, elbClient, elbClassicClient, ec2Client):
        super().__init__()
        self.asg = asg
        self.asgClient = asgClient
        self.elbClient = elbClient
        self.elbClassicClient = elbClassicClient
        self.ec2Client = ec2Client

        self._resourceName = asg['AutoScalingGroupName']

        self.init()
        
    def  _checkELBHealthCheckWithoutAssociation(self):
        asg = self.asg
        if asg['HealthCheckType'] == 'ELB' and len(asg['LoadBalancerNames']) == 0 and len(asg['TargetGroupARNs']) == 0:
            self.results['ASGELBHealthCheckValidation'] = [-1, '']
        
        return
    
    def _checkELBHealthCheckEnabled(self):
        asg = self.asg
        
        if (len(asg['LoadBalancerNames']) > 0 or len(asg['TargetGroupARNs']) > 0) and asg['HealthCheckType'] != 'ELB':
            self.results['ASGELBHealthCheckEnabled'] = [-1, '']
        
        return
    
    def _checkTargetGroupInstancesRemoved(self):
        asg = self.asg
        results = self.asgClient.describe_load_balancer_target_groups(
            AutoScalingGroupName = asg['AutoScalingGroupName']
        )
        
        targetGroups = results['LoadBalancerTargetGroups']
        for group in targetGroups:
            if group['State'] == 'Removed':
                self.results['ASGInstancesRemoved'] = [-1, group['State']]
                
        return
    
    def _checkTargetGroupELBAssociation(self):
        asg = self.asg
        
        if len(asg['TargetGroupARNs']) == 0:
            return
        
        results = self.elbClient.describe_target_groups(
            TargetGroupArns = asg['TargetGroupARNs']
        )
        
        for group in results['TargetGroups']:
            if len(group['LoadBalancerArns']) == 0:
                self.results['ASGTargetGroupELBExist'] = [-1, '']
                return
        return
    
    def _checkClassicLBAssociation(self):
        asg = self.asg
        if len(asg['LoadBalancerNames']) == 0:
            return
        
        result = self.elbClassicClient.describe_load_balancers()
        for lb in result['LoadBalancerDescriptions']:
            if lb['LoadBalancerName'] in asg['LoadBalancerNames']:
                return
            
        self.results['ASGClassicLBExist'] = [-1, asg['LoadBalancerNames']]
        
        return
        
    def _checkAMIExist(self):
        asg = self.asg
        imageId = ''
        
        if 'LaunchConfigurationName' in asg:
            launchConfig = asg['LaunchConfigurationName']
            
            result = self.asgClient.describe_launch_configurations(
                LaunchConfigurationNames = [launchConfig]
            )
            
            for config in result['LaunchConfigurations']:
                imageId = config['ImageId']
                
                if config.get('MetadataOptions') is None:
                    self.results['ASGIMDSv2'] = [-1, '']
                else:
                    if config.get('MetadataOptions').get('HttpTokens') == 'optional':
                        self.results['ASGIMDSv2'] = [-1, 'Optional']
                
        elif 'MixedInstancesPolicy' in asg:
            templateInfo = asg['MixedInstancesPolicy']['LaunchTemplate']['LaunchTemplateSpecification']
            templateId = templateInfo['LaunchTemplateId']
            tempalteVersion = templateInfo['Version']
            
            templateResult = self.ec2Client.describe_launch_template_versions(
                LaunchTemplateId = templateId,
                Versions = [tempalteVersion]
            )
            
            for version in templateResult['LaunchTemplateVersions']:
                imageId = version.get('LaunchTemplateData').get('ImageId')
                if version.get('LaunchTemplateData').get('MetadataOptions') is None:
                    self.results['ASGIMDSv2'] = [-1, '']
                else:
                    if version.get('LaunchTemplateData').get('MetadataOptions').get('HttpTokens') == 'optional':
                        self.results['ASGIMDSv2'] = [-1, 'Optional']
        else:
            return
        
        try:
            imgResult = self.ec2Client.describe_images(
                ImageIds = [imageId]
            )
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                self.results['ASGAMIExist'] = [-1, imageId]
            else:
                raise(error)
            
        
        return