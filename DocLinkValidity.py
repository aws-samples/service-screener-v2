import os
import sys
import json
import re
from urllib.request import Request, urlopen
import urllib.error

from utils.RuleReader import RuleReader

SERVICE_FOLDER_PATH = os.getcwd() + '/services'

if __name__ == "__main__":
    attrName = 'ref'
    rr = RuleReader(SERVICE_FOLDER_PATH)
    
    
    ruleList = rr.getRulesAttr(attrName)
    invalidRefDict = {
        'NoRef': [],
        'InvalidSyntax': []
    }
    
    for rule in ruleList:
        for ref in ruleList[rule][attrName]:
            if ref.strip() == '':
                invalidRefDict['NoRef'].append(rule)
                continue
            output = re.search(r'<(.*)>', ref)
            if output is None:
                invalidRefDict['InvalidSyntax'].append(rule)
                continue
            try:
                url = output.group(1)
                if url.strip() == '':
                    invalidRefDict['NoRef'].append(rule)
                    continue
                
                print('.', end="", flush=True)
                conn = Request(url)
                conn.add_header('User-Agent', 'aws-cli')
                resp = urlopen(conn)
            
                if resp.getcode() != 200:
                    if e.code not in invalidRefDict:
                        invalidRefDict[resp.getcode()] = []
                    invalidRefDict[resp.getcode()].append({rule: url})
            except urllib.error.HTTPError as e:
                if e.code not in invalidRefDict:
                    invalidRefDict[e.code] = []
                invalidRefDict[e.code].append({rule: url})
            except Exception as e:
                print(e)
                if 'UnknownError' not in invalidRefDict:
                    invalidRefDict['UnknownError'] = []
                invalidRefDict['UnknownError'].append({rule: e})
                
                
    print('')            
    print(invalidRefDict)