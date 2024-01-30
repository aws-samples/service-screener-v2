import json

class Policy:
    fullAccessList = {
        'oneService': False,
        'fullAdmin': False
    }
    
    publicAccess = False
    
    def __init__(self, document):
        self.fullAccessList = {
            'oneService': False,
            'fullAdmin': False
        }
        
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
            
            elif 'NotAction' in statement:
                self.fullAccessList['oneService'] = True
                    
        return False
        
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