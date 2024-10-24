import boto3
import re
import time

from pprint import pprint
from utils.Config import Config
from typing import Set, Dict, Union
from netaddr import IPAddress

## from utils.Tools import _pi
def _pi(group, res=''):
    det = ''
    if res: 
        det = '- '
    print("... \x1b[1;37;44m({})\x1b[0m {}\x1b[1;37;45m{}\x1b[0m".format(group, det, res))

def _pr(s, forcePrint = False):
    DEBUG = Config.get('DEBUG')
    if forcePrint or DEBUG == True:
        print(s)

def _info(s, alwaysPrint = False):
    _printStatus("info", s, alwaysPrint)

def _warn(s, forcePrint=True):
    _printStatus("\033[1;41m__!! WARNING !!__\033[0m", s, forcePrint)
    
def _printStatus(status, s, forcePrint = False):
    p = "["+status+"] "+ s
    _pr(p, forcePrint)

def checkIsPrivateIp(ipaddr):
    ip = ipaddr.split('/')
    return IPAddress(ip[0]).is_private()

def aws_parseInstanceFamily(instanceFamily: str, region=None) -> Dict[str, str]:
    if region:
        CURRENT_REGION = region
    else:
        CURRENT_REGION = Config.CURRENT_REGION

    arr = instanceFamily.split('.')
    if len(arr) > 3 or len(arr) == 1:
        # for invalid strings
        return instanceFamily

    if len(arr) == 3 and arr[0].lower() == "db":
        p = arr[1]
        s = arr[2]
    else:
        p = arr[0]
        s = arr[1]

    patterns = r"([a-zA-Z]+)(\d+)([a-zA-Z]*)"
    output = re.search(patterns, p)

    cpu = memory = 0

    family = p+'.'+s
    CACHE_KEYWORD = 'INSTANCE_SPEC::' + family
    spec = Config.get(CACHE_KEYWORD, [])
    ssBoto = Config.get('ssBoto', None)
    if not spec:
        ec2c = ssBoto.client('ec2', region_name=CURRENT_REGION)
        resp = ec2c.describe_instance_types(InstanceTypes=[family])
        
        iType = resp.get('InstanceTypes')
        if iType:
            info = iType[0]
            cpu = info['VCpuInfo']['DefaultVCpus']
            memory = round(info['MemoryInfo']['SizeInMiB']/1024, 2)

        spec = {
            'vcpu': cpu,
            'memoryInGiB': memory
        }

        Config.set(CACHE_KEYWORD, spec)

    result = {
        "full": instanceFamily,
        "prefix": p,
        "suffix": s,
        "specification": spec,
        "prefixDetail": {
            "family": output.group(1),
            "version": output.group(2),
            "attributes": output.group(3),
        }
    }

    return result


def aws_get_latest_instance_generations(instanceFamilyList: Set[str]) -> Set[str]:
    '''
    example:
      input: set(['t4g','t3a','t2','m5'])
      output: set(['t4g','m5'])
    '''

    def parse_instance_family_to_dict(name: str) -> Dict[str, Union[str, int]]:
        idx = 0
        family = ""
        gen = ""
        attrib = ""
        for idx in range(len(name)):
            if str.isalpha(name[idx]):
                if len(gen) == 0:
                    family += name[idx]
                attrib += name[idx]
            if str.isdigit(name[idx]):
                gen += name[idx]
        return {"family": family, "gen": int(gen), "attrib": attrib}

    q = dict()
    q_attribs = dict()

    for i in [parse_instance_family_to_dict(i) for i in instanceFamilyList]:
        if i['family'] not in q.keys():
            q[i['family']] = i['gen']
            q_attribs[i['family']] = [i['attrib']]
        elif q[i['family']] < i['gen']:
            q[i['family']] = i['gen']
            q_attribs[i['family']] = [i['attrib']]
        elif q[i['family']] == i['gen']:
            q_attribs[i['family']].append(i['attrib'])

    return set([e for sublist in [[f"{i}{q[i]}{v}" for v in q_attribs[i]] for i in q.keys()] for e in sublist])


if __name__ == "__main__":
    Config.init()
    l = [
        "nocomment",
        "c5.2xlarge",
        "c6gn.4xlarge",
        "db.r6g.xlarge",
        "t4g.xlarge.search"
    ]

    for v in l:
        o = aws_parseInstanceFamily(v)
        print(o)
