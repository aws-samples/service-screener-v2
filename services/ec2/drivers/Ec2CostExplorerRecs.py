import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2CostExplorerRecs(Evaluator):

    def __init__(self,ceClient):
        super().__init__()
        self.ceClient = ceClient

        self._resourceName = 'ReservedInstance&SavingPlans'

        self.init()

   # checks

    def _checkRIRecommendations(self):
        results = {}
        try:
            results = self.ceClient.get_reservation_purchase_recommendation(
                Service = 'Amazon Elastic Compute Cloud - Compute'
            )
            
            if len(results['Recommendations']) > 0:
                self.results['CEReservedInstance'] = ['-1','']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
        except Exception as e:
            print('Reserved Instance recommendation API call is getting the following error:')
            print(e)

        return

    def _checkSPRecommendations(self):
        try:
            results = self.ceClient.get_savings_plans_purchase_recommendation(
                LookbackPeriodInDays = 'THIRTY_DAYS',
                PaymentOption = 'NO_UPFRONT',
                SavingsPlansType = 'COMPUTE_SP',
                TermInYears = 'ONE_YEAR'
            )
            if len(results['SavingsPlansPurchaseRecommendation']) > 0:
                self.results['CESavingsPlans'] = ['-1','']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)        
        except Exception as e:
            print('Compute Savings Plans recommendation API call is getting the following error:')
            print(e) 

        return 