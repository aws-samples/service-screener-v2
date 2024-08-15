import boto3, botocore, json
from simple_term_menu import TerminalMenu

## Setting
defaultOrgazinationAccountAccessRole = 'OrganizationAccountAccessRole'

org = boto3.client('organizations')
acctLists = []

sts = boto3.client('sts')
resp = sts.get_caller_identity()
myAccountId = resp.get('Account')


## Welcome
print("Welcome to Service-Screener-v2 helper: OrganizationAccountsJson Generator")
print("You are currently in this account: \033[4m{}\033[0m, which will be automatically included in the scan".format(myAccountId))
print()
print("Select the accounts to be included into the list")

params = {}
hasNextToken = True
while(hasNextToken):
    try:
        resp = org.list_accounts(**params)
        accts = resp.get('Accounts')
        acctLists = acctLists + accts

        hasNextToken = resp.get('NextToken')
        params['NextToken'] = hasNextToken
    except botocore.exceptions.ClientError as e:
        print(e.response['Error']['Code'])
        exit()

# Build multiselect cli
print("=================================================")
mlist = [f"{acct['Id']}::{acct['Name']}" for acct in acctLists if acct['Status'] == 'ACTIVE' and acct['Id'] != myAccountId]

# print(mlist)
tMenu = TerminalMenu(
    mlist,
    multi_select=True,
    show_multi_select_hint=True
)

tControl = tMenu.show()
accounts = tMenu.chosen_menu_entries

# print
accessRole = input("Enter organization cross accounts role (Leave it blank to use the default role: [{}]): ".format(defaultOrgazinationAccountAccessRole))

## check if accessRole is empty after trim  
if accessRole.strip() == '':
    accessRole = defaultOrgazinationAccountAccessRole

# print(accessRole)

#Get ExternalId
externalId = input("Enter your external id (leave it blank if NONE): ")
# print(externalId)

#Summary before general the JSON files


print()
print("===================Summary=======================")
print("({}) Accounts selected, they are: {}".format(len(accounts), accounts))
print("OrganizationAccessRole: {}".format(accessRole))
print("ExternalId: {}".format(externalId))
print("=================================================")
confirm = input("Confirm to proceed JSON output creation? (y/n) ")
if confirm.upper() == 'N':
    print("User decided not to proceed, operation cancelled")
else:
    selected = {}
    for acct in accounts:
        acctId = acct.split('::')[0]
        selected[acctId] = {}
        
    general = {
        'IncludeThisAccount': True,
        'RoleName': accessRole,
        'ExternalId': externalId
    }

    crossAccountsJson = {'general': general, 'accountLists': selected}
    ## write the JSON into a filepath
    with open('crossAccounts.json', 'w') as outfile:
        json.dump(crossAccountsJson, outfile, indent=4)

    print("JSON file generated: crossAccounts.json")
    print("You can now run ``` screener --regions ALL --crossAccounts 1 ``` to perform cross accounts scan")