import json
from utils.Config import Config
from utils.CustomPage.CustomObject import CustomObject

import boto3
from botocore.exceptions import ClientError
from datetime import datetime
from collections import defaultdict

class TA(CustomObject):
    # SHEETS_TO_SKIP = ['Info', 'Appendix']
    taFindings = {}
    taError = ''
    ResourcesToTrack = {}
    def __init__(self):
        super().__init__()
        return
    
    def build(self):
        print("... Running CP - TA, it can takes up to 60 seconds")
        ssBoto = Config.get('ssBoto')
        ta_client = ssBoto.client('trustedadvisor', region_name='us-east-1')
        findings = defaultdict(lambda: defaultdict(list))
    
        try:
            pillars = ['cost_optimizing', 'security', 'performance', 'fault_tolerance', 'service_limits', 'operational_excellence']

            # First check if user has access to Trusted Advisor
            try:
                # Test API access with a simple call
                ta_client.list_recommendations(pillar='security', maxResults=1)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'SubscriptionRequiredException':
                    errMsg = "Error: Your AWS account doesn't have the required Business or Enterprise Support plan for Trusted Advisor access."
                    self.taError = errMsg
                    print(errMsg)
                    return
                elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:                    
                    # errMsg = "Error: You don't have sufficient permissions to access Trusted Advisor. Required IAM permissions: trustedadvisor:List*, trustedadvisor:Get*"
                    errMsg = e.response['Error']['Message']
                    self.taError = errMsg
                    print(errMsg)
                    return
                else:
                    raise e

    
            for pillar in pillars:
                try:
                    # Get recommendations for each pillar
                    recommendations = ta_client.list_recommendations(
                        pillar=pillar
                    )['recommendationSummaries']

                    active_recommendations = [
                        recomm for recomm in recommendations 
                        if recomm['status'] not in ['resolved', 'dismissed']
                    ]
                    
                    # Process each recommendation
                    for recomm in active_recommendations:
                        # Get detailed recommendation information
                        detailed_recomm = ta_client.get_recommendation(
                            recommendationIdentifier=recomm['arn']
                        )['recommendation']
                        
                        # Create recommendation data structure
                        recomm_data = {
                            'name': recomm['name'],
                            'description': detailed_recomm.get('description', 'N/A'),
                            'status': recomm['status'],
                            'source': recomm.get('source', 'N/A'),
                            'last_updated': recomm.get('lastUpdatedAt', 'N/A'),
                            'lifecycle_stage': recomm.get('lifecycleStage', 'N/A'),
                            'error_count': recomm.get('resourcesAggregates', {}).get('errorCount', 0),
                            'warning_count': recomm.get('resourcesAggregates', {}).get('warningCount', 0),
                            'ok_count': recomm.get('resourcesAggregates', {}).get('okCount', 0)
                        }
                        
                        # Add cost optimization specific data
                        if pillar == 'cost_optimizing':
                            cost_data = recomm.get('pillarSpecificAggregates', {}).get('costOptimizing', {})
                            recomm_data.update({
                                'estimated_savings': cost_data.get('estimatedMonthlySavings', 0),
                                'estimated_percent_savings': cost_data.get('estimatedPercentMonthlySavings', 0)
                            })
                        
                        # Group by service
                        for service in recomm.get('awsServices', ['UNKNOWN']):
                            findings[pillar][service].append(recomm_data)
                
                except Exception as e:
                    errMsg = f"Error processing pillar {pillar}: {str(e)}"
                    self.taError = errMsg
                    print(errMsg)
                    continue
            
            # Print detailed findings
            for pillar, services in findings.items():
                # reset info
                secTitle = ""
                secTotal = {"Error": 0, "Warning": 0, "OK": 0}
                tabDetail = []
                thead = ["Services", "Findings", "# Error", "# Warning", "# OK", "Last Updated"]
                if pillar == 'cost_optimizing':
                    thead.append("Estimated Monthly Savings")
                    thead.append("Estimated Percent Savings")

                secTitle = pillar.upper()
                self.taFindings[secTitle] = []
                rowInfo = []
                for service, recommendations in services.items():
                    total_error = sum(r['error_count'] for r in recommendations)
                    total_warning = sum(r['warning_count'] for r in recommendations)
                    total_ok = sum(r['ok_count'] for r in recommendations)
                    
                    # print(f"Total Resources: Error({total_error}) Warning({total_warning}) OK({total_ok})")
                    secTotal['Error'] += total_error    
                    secTotal['Warning'] += total_warning
                    secTotal['OK'] += total_ok
                    
                    # Print individual recommendations
                    for recomm in recommendations:
                        detail = [service]

                        statClass = 'success'
                        if recomm['status'] == 'error':
                            statClass = 'danger'
                        elif recomm['status'] == 'warning':
                            statClass = 'warning'
                            
                        statusStr = "<span class='badge badge-{}'>{}</span>".format(statClass, recomm['status'].upper())

                        detail.append(f"{statusStr} {recomm['name']} <i>(Source: {recomm['source']})</i>")
                        # detail.append(f"{recomm['name']} <i>(Source: {recomm['source']})</i>")
                        detail.append(f"{recomm['error_count']}")
                        detail.append(f"{recomm['warning_count']}")
                        detail.append(f"{recomm['ok_count']}")

                        parsed_datetime = datetime.fromisoformat(f"{recomm['last_updated']}")
                        formatted_datetime = parsed_datetime.strftime('%Y-%m-%d %H:%M:%S')
                        detail.append(f"{formatted_datetime} UTC")
                        
                        if pillar == 'cost_optimizing':
                            detail.append(f"${recomm['estimated_savings']:,.2f}")
                            detail.append(f"{recomm['estimated_percent_savings']:.1f}%")

                        detail.append(f"{recomm['description']}")
                        rowInfo.append(detail)

                self.taFindings[secTitle] = [rowInfo, thead, secTotal.copy()]
                # formatOutput(secTitle, [0,0,0], thead, rowInfo)

        except Exception as e:
            print(f"Error: {str(e)}")