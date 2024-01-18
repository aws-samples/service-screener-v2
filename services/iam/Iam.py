import botocore

import json
import time

from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
from services.iam.drivers.IamRole import IamRole
from services.iam.drivers.IamGroup import IamGroup
from services.iam.drivers.IamUser import IamUser
from services.iam.drivers.IamAccount import IamAccount

class Iam(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.iamClient = ssBoto.client('iam', config=self.bConfig)
        
        self.awsClients = {
            'iamClient': self.iamClient,
            'orgClient': ssBoto.client('organizations'),
            'accClient': ssBoto.client('account', config=self.bConfig),
            'sppClient': ssBoto.client('support', config=self.bConfig),
            'gdClient': ssBoto.client('guardduty', config=self.bConfig),
            'budgetClient': ssBoto.client('budgets', config=self.bConfig),
            'curClient': ssBoto.client('cur', config=self.bConfig),
            'ctClient': ssBoto.client('cloudtrail', config=self.bConfig)
        }
    
    def getGroups(self):
        arr = []
        results = self.iamClient.list_groups()
        arr = results.get('Groups')
        
        while results.get('Marker') is not None:
            results = self.iamClient.list_groups(
                Marker = results.get('Marker')
            )
            arr = arr + results.get('Groups')
            
        return arr
    
    def getRoles(self):
        arr = []
        results = self.iamClient.list_roles()
        for v in results.get('Roles'):
            if (v['Path'] != '/service-role/' and v['Path'][0:18] != '/aws-service-role/') and (self._roleFilterByName(v['RoleName'])):
                arr.append(v)
                
        while results.get('Marker') is not None:
            results = self.iamClient.list_roles(Marker=results.get('Marker'))
            for v in results.get('Roles'):
                if (v['Path'] != '/service-role/' and v['Path'][0:18] != '/aws-service-role/') and (self._roleFilterByName(v['RoleName'])):
                    arr.append(v)
        
        return arr
        
    def getUsers(self):
        self.getUserFlag = True
        arr = []
        
        try: 
            results = self.iamClient.get_credential_report()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ReportNotPresent' or e.response['Error']['Code'] == 'ReportExpired':
                resp = self.iamClient.generate_credential_report()
                print('Generating IAM Credential Report...')
                time.sleep(5)
        
        currCount = 0
        MAX_LOOPS = 5
        while not 'results' in locals() and currCount < MAX_LOOPS: 
            try:
                results = self.iamClient.get_credential_report()
            except botocore.exceptions.ClientError as e:
                currCount = currCount + 1
                if e.response['Error']['Code'] == 'ReportInProgress':
                    print('IAM Credential is still genererating, current counter: ' + str(currCount))
                elif e.response['Error']['Code'] == 'ReportExpired':
                    resp = self.iamClient.generate_credential_report()
                    print('IAM Credential expired, regenerating... : ' + str(currCount))
                else:
                    print('Unexpected error: ', e.response['Error']['Code'])
                    currCount = 10 #skip the loop entirely
                time.sleep(5)
            
        
        if not 'results' in locals():
            print('IAM Users scan will be skip, unable to acquire IamCredentialReports')
            return []
        
        rows = results.get('Content')
        rows = rows.decode('UTF-8')
        
        row = rows.split("\n")
        
        fields = row[0].split(',')
        del row[0]
        for temp in row:
            arr.append(dict(zip(fields, temp.split(','))))
        
        return arr
        
    def advise(self):
        objs = {}
        
        users = self.getUsers()
        if self.getUserFlag == False:
            return objs
        
        for user in users:
            print('... (IAM::User) inspecting ' + user['user'])
            obj = IamUser(user, self.iamClient)
            obj.run(self.__class__)
            
            identifier = "<b>root_id</b>" if user['user'] == "<root_account>" else user['user']
            objs['User::' + identifier] = obj.getInfo()
            del obj
        
        roles = self.getRoles()
        for role in roles:
            print('... (IAM::Role) inspecting ' + role['RoleName'])
            obj = IamRole(role, self.iamClient)
            obj.run(self.__class__)
            
            objs['Role::' + role['RoleName']] = obj.getInfo()
            del obj

        groups = self.getGroups()
        for group in groups:
            print('... (IAM::Group) inspecting ' + group['GroupName'])
            obj = IamGroup(group, self.iamClient)
            obj.run(self.__class__)
            
            objs['Group::' + group['GroupName']] = obj.getInfo()
            del obj
            
        print('... (IAM:Account) inspecting')
        obj = IamAccount(None, self.awsClients, users, roles)
        obj.run(self.__class__)
        objs['Account::Config'] = obj.getInfo()
        
        return objs
    
    def _roleFilterByName(self, rn):
        keywords = [
            'AmazonSSMRole',
            'DO-NOT-DELETE',
            'Isengard',
            'AwsSecurityNacundaAudit',
            'AwsSecurityAudit',
            'GatedGarden',
            'PVRE-SSMOnboarding',
            'PVRE-Maintenance',
            'InternalAuditInternal'
        ]
        
        for kw in keywords:
            if kw in rn:
                return False
        return True
        
if __name__ == "__main__":
    Config.init()
    o = Iam('us-east-1')
    out = o.advise()
    _pr(out)
    
