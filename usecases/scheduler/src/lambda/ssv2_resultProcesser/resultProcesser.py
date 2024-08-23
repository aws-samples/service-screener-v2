import boto3 
import json
from datetime import datetime
from dateutil.relativedelta import relativedelta
import os
import openpyxl
import logging

## Initialization
SnsEmailSubject = "[AWS] Service Screener Scheduler Report"
SnsEmailBodyPrefix = "Here is your Service Screener report.\n\n"
snsPrefix = os.environ['SSV2_SNSARN_PREFIX']


successResp = {
    'statusCode': 200,
    'body': 'success'
}

currentResults = {}
previousResults = {}
accounts = {}

SHEETS_TO_SKIP = ['Info', 'Appendix']

def lambda_handler(event, context):
    record = event['detail']
    region = event['region']
    targetBucket = record['bucket']['name']
    targetObject = record['object']['key']
    
    s3 = boto3.client('s3', region_name=region)
    sns = boto3.client('sns', region_name=region)
    
    filepath = targetObject.split('/')
    configId = filepath[0]
    currentDate = filepath[1]

    objs = s3.list_objects_v2(Bucket=targetBucket, Prefix=configId + '/' + currentDate + '/')
    contents = objs.get('Contents')
    for xlsx in contents:
        if xlsx.get('Key').endswith('xlsx'):
            _obj = xlsx.get('Key').split('/')
            accounts[_obj[2]] = {'currentRun': currentDate}

    # find latest available filesx
    currentDateObj = datetime.strptime(currentDate, '%Y%m%d').date()
    for x in range(3):
        prefixSearch = (currentDateObj - relativedelta(months=x)).strftime("%Y%m")
        objs = s3.list_objects_v2(Bucket=targetBucket, Prefix=configId + '/' + prefixSearch)
        contents = objs.get('Contents')
        if not contents:
            continue 

        contents.reverse()
        for file in contents:
            _file = file.get('Key')
            if _file.endswith('xlsx'):
                info = _file.split('/')
                acct = info[2]
                if acct in accounts and accounts[acct].get('previousRun') == None and info[1] != currentDate:
                    accounts[acct]['previousRun'] = info[1]

        if checkIfPreviousScanFound() == True:
            break

    html = []
    for acct, info in accounts.items():
        html.append("\n AccountId: {} \n".format(acct))
        html.append( processXlsx(s3, targetBucket, configId, acct, info) )
    
    res = sendSnsEmail(sns, configId, html)
    if res[0] == False:
        return  {
            'statusCode': 500,
            'body': res[1]
        }

    return successResp

def processXlsx(s3, targetBucket, configId, acct, info):
    latestObjname = "{}/{}/{}/workItem.xlsx".format(configId, info['currentRun'], acct)
    s3.download_file(targetBucket, latestObjname, '/tmp/current.xlsx')
    
    loadXlsx('/tmp/current.xlsx')

    previousObjname = None
    hasPreviousObj = False
    if 'previousRun' in info:
        hasPreviousObj = True
        previousObjname = "{}/{}/{}/workItem.xlsx".format(configId, info['previousRun'], acct)
        s3.download_file(targetBucket, previousObjname, '/tmp/previous.xlsx')
        loadXlsx('/tmp/previous.xlsx')

    compared = compareXlsx(hasPreviousObj)
    html = formatCompared(compared, hasPreviousObj)
    
    os.remove('/tmp/current.xlsx')
    os.remove('/tmp/previous.xlsx')

    return html

def loadXlsx(filename):
    wb = openpyxl.load_workbook(filename)
    for sheetName in wb.sheetnames:
        if sheetName in SHEETS_TO_SKIP:
            continue

        results = []
        hcnt = 0
        tcnt = 0

        ws = wb[sheetName]
        for row in ws.iter_rows(min_row=2, values_only=True):
            _row = list(row)
            if _row[0] == 'Region':
                continue

            if _row[4] == 'High':
                hcnt = hcnt + 1

            del _row[5]
            tcnt = tcnt + 1

            results.append('::'.join(_row))
            
        if filename == '/tmp/current.xlsx':
            currentResults[sheetName] = {'obj': results, 'High': hcnt, 'Total': tcnt}
        else:
            previousResults[sheetName] = {'obj': results, 'High': hcnt, 'Total': tcnt}

def compareXlsx(hasPreviousObj):
    data = []
    for sheets in currentResults:
        newFindings = []
        resolvedItems = []
        if hasPreviousObj:
            diff = list(set(currentResults[sheets]['obj']) - set(previousResults[sheets]['obj']))
            newFindings = diff
            
            diff = list(set(previousResults[sheets]['obj']) - set(currentResults[sheets]['obj']))
            resolvedItems = diff
        
        nf = ""
        ri = ""
        if len(newFindings):
            nf = " -- " + ("\n -- ").join(newFindings)

        if len(resolvedItems):
            ri = " -- " + ("\n -- ").join(resolvedItems)

        data.append([
            sheets,
            currentResults[sheets]['High'],
            currentResults[sheets]['Total'],
            currentResults[sheets]['High'] - previousResults[sheets]['High'],
            currentResults[sheets]['Total'] - previousResults[sheets]['Total'],
            nf,
            ri,
            len(newFindings),
            len(resolvedItems)
        ])
        logging.info(data)

    return data

def formatCompared(compared, hasPreviousObj):
    row = []
    news = []
    resolved = []
    totalNew = 0
    totalResolved = 0
    for trow in compared:
        tmsg = ""
        tmsg = "{}: HIGH={} | TOTAL={}".format(trow[0], trow[1], trow[2])
        if hasPreviousObj:
            tmsg  = tmsg + " | DIFFHIGH={} | TOTALDIFF={}".format(trow[3], trow[4])
            if len(trow[5]):
                totalNew = totalNew + trow[7]
                news = news + [trow[5]]
            
            if len(trow[6]):
                totalResolved = totalResolved + trow[8]
                resolved = resolved + [trow[6]]

        row.append(tmsg)

    html = "\n".join(row)
    html = html + "\n\n"
    html = html + "\nNew Findings ({}):\n".format(totalNew)
    html = html + ''.join(news)
    html = html + "\n\n"
    html = html + "\nResolved ({}):\n".format(totalResolved)
    html = html + "\n -- ".join(resolved)

    return html


# Not in used, SNS does not support HTML unless pairing it with SES
def formatComparedHTML(compared, hasPreviousObj):

    template = "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>"

    thead = ["Services", "# High", "# Total"]
    if hasPreviousObj:
        thead.append('# High (diff)')
        thead.append('# Total (diff)')
        thead.append("New Findings")
        thead.append("Resolved")

    theadHTML = ''.join(["<th>{}</th>".format(x) for x in thead])
    
    tbodyHTML = []
    for row in compared:
        trow = [row[0], row[1], row[2]]
        if hasPreviousObj:
            trow.append(row[3])
            trow.append(row[4])
            trow.append(row[5])
            trow.append(row[6])
        
        tbodyStr = ''.join(["<td>{}</td>".format(x) for x in trow])
        tbodyHTML.append("<tr>{}</tr>".format(tbodyStr))
    
    tbodyHTML = ''.join(tbodyHTML)
    return template.format(theadHTML, tbodyHTML)

def checkIfPreviousScanFound():
    for acct, info in accounts.items():
        if not info.get('previousRun'):
            return False

    return True
    pass

def sendSnsEmail(sns, configId, html):
    topic = snsPrefix + '-' + configId
    rrr = sns.list_topics()
    topicArn = [tp['TopicArn'] for tp in sns.list_topics()['Topics'] if topic in tp['TopicArn']]

    if len(topicArn) == 0:
        return [False, 'No SNS topic found']

    sns.publish(
        TopicArn=topicArn[0],
        Message= SnsEmailBodyPrefix + ''.join(html),
        Subject= SnsEmailSubject
    )

    return [True, 'Sent']


#with open('sampleS3Event.json', 'r') as f:
#    event = json.load(f)

# output = lambda_handler(event, '')
# print(output)