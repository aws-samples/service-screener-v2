import argparse

class ArguParser:
    OPTLISTS = {
        "r": "regions",
        "s": "services",
        "l": "log",
        "d": "debug",
        "t": "test",
        "p": "profile",
        "b": "bucket",
        "f": "filters",
        "u": "suppress_file"
    }
    
    CLI_ARGUMENT_RULES = {
        "regions": {
            "required": False, 
            # "errmsg": "Please key in --region, example: --region ap-southeast-1",
            "default": None,
            "help": "--regions ap-southeast-1,ap-southeast-2"
        },
        "services": {
            "required": False,
            "emptymsg": "Missing --services, using default value: $defaultValue",
            "default": "rds,ec2,iam,s3,efs,lambda,guardduty,cloudfront,cloudtrail,elasticache,eks,dynamodb,opensearch,kms,cloudwatch,redshift,apigateway,sqs",
            "help": "--services ec2,iam"
        },
        "debug": {
            "required": False,
            "default": False,
            "help": "--debug True|False"
        },
        "log": {
            "required": False,
            "default": None
        },
        ## Removing Feedback
        # "feedback": {
        #     "required": False,
        #    "default": False
        # },
        ## Conflict params
        #"dev": {
        #    "required": False,
        #    "default": False
        #},
        "ztestmode": {
            "required": False,
            "default": False
        },
        "profile": {
            "required": False,
            "default": False
        },
        "tags": {
            "required": False,
            "default": False
        },
        "frameworks": {
            "required": False,
            "default": 'MSR,FTR,SSB,WAFS,CIS,NIST,RMiT,SPIP,RBI'
        },
        "others":{
            "required": False,
            "default": None,
            "help": "reserved for future development"
        },
        'crossAccounts':{
            "required": False,
            "default": False,
            "help": "Screener to run multiple accounts"
        },
        'workerCounts':{
            "required": False,
            "default": 4,
            "help": "Number of parallel threads, recommend 4 for Cloudshell"
        },
        'beta': {
            "required": False,
            "default": False,
            "help": "Enable Beta features"
        },
        'suppress_file': {
            "required": False,
            "default": None,
            "help": "Path to JSON file containing suppressions"
        }
    }

    @staticmethod
    def Load():
        parser = argparse.ArgumentParser(prog='Screener', description='Service-Screener, open-source to check your AWS environment against AWS Well-Architected Pillars')
    
        for k, v in ArguParser.CLI_ARGUMENT_RULES.items():
            # Get the short option from OPTLISTS if available, otherwise no short option
            short_opt = None
            for short, long in ArguParser.OPTLISTS.items():
                if long == k:
                    short_opt = short
                    break
            
            if short_opt:
                parser.add_argument('-' + short_opt, '--' + k, required=v['required'], default=v['default'], help=v.get('help', None))
            else:
                parser.add_argument('--' + k, required=v['required'], default=v['default'], help=v.get('help', None))
        
        parser.allow_abbrev = False
        args = vars(parser.parse_args())
        
        return args
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Screener', description='Service-Screener, open-source to check your AWS environment against AWS Well-Architected Pillars')
    
    for k, v in ArguParser.CLI_ARGUMENT_RULES.items():
        parser.add_argument('-' + k[:1], '--' + k, required=v['required'], default=v['default'], help=v.get('help', None))
    
    args = parser.parse_args()
    print(args.region)
