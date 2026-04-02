import os
import re
from urllib.request import Request, urlopen
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.RuleReader import RuleReader

SERVICE_FOLDER_PATH = os.getcwd() + '/services'

def check_url(rule, url):
    try:
        conn = Request(url)
        conn.add_header('User-Agent', 'aws-cli')
        resp = urlopen(conn, timeout=10)
        code = resp.getcode()
        if code != 200:
            return (code, {rule: url})
    except urllib.error.HTTPError as e:
        return (e.code, {rule: url})
    except Exception as e:
        return ('UnknownError', {rule: str(e)})
    return None

if __name__ == "__main__":
    attrName = 'ref'
    rr = RuleReader(SERVICE_FOLDER_PATH)
    ruleList = rr.getRulesAttr(attrName)
    invalidRefDict = {
        'NoRef': [],
        'InvalidSyntax': []
    }

    tasks = []
    for rule in ruleList:
        for ref in ruleList[rule][attrName]:
            if ref.strip() == '':
                invalidRefDict['NoRef'].append(rule)
                continue
            output = re.search(r'<(.*)>', ref)
            if output is None:
                invalidRefDict['InvalidSyntax'].append(rule)
                continue
            url = output.group(1)
            if url.strip() == '':
                invalidRefDict['NoRef'].append(rule)
                continue
            tasks.append((rule, url))

    print(f"Checking {len(tasks)} URLs with 10 parallel workers...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_url, rule, url): (rule, url) for rule, url in tasks}
        done = 0
        for future in as_completed(futures):
            done += 1
            print(f"\r{done}/{len(tasks)}", end="", flush=True)
            result = future.result()
            if result:
                key, entry = result
                if key not in invalidRefDict:
                    invalidRefDict[key] = []
                invalidRefDict[key].append(entry)

    print('')
    print(invalidRefDict)
