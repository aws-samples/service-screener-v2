import sys

import boto3
from botocore.config import Config as bConfig
from utils.Config import Config
from utils.Tools import _warn, _info

class AwsRegionSelector:

    @staticmethod
    def get_all_enabled_regions(minimal=False):
        DEBUG = Config.get('DEBUG')
        if not minimal and AwsRegionSelector.prompt_confirm_get_all_regions() == False:
            sys.exit('__SCRIPT HALT__, user decided not to proceed')
        
        conf = bConfig(
            region_name = 'us-east-1'    
        )
        acct = boto3.client('account')
        
        results = {}
        regions = []
        token = None
        while True:
            if token == None:
                results = acct.list_regions(
                    RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'],
                    MaxResults=20
                )
            else:
                results = acct.list_regions(
                    RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'],
                    NextToken = token,
                    MaxResults=20
                )
            
            token = results.get('NextToken')
            for info in results.get('Regions'):
                regions.append(info['RegionName'])
            
            if not token:
                break
        
        if DEBUG and not minimal:
            _info("The following region(s) are enabled/opt-in")
            _info('[' + str(len(regions)) + "] | " + ', '.join(regions))
        
        return regions
        
    @staticmethod
    def prompt_confirm_get_all_regions():
        print()
        _warn("You specify --regions as ALL. It will loop through all ENABLED/OPT-IN regions and it is going to take sometime to complete.")

        attempt = 0
        while True:
            if attempt > 0:
                _warn("You have entered an invalid option. Please try again.")
            
            confirm = input("Do you want to process? Please enter 'y' for yes, 'n' for no: ").lower()
            attempt += 1
            if confirm in ['y', 'n']:
                break
        
        if confirm == 'y':
            return True
        
        return False
        
    @staticmethod
    def prompt_for_region():
        regions = AwsRegionSelector.get_all_enabled_regions(minimal=True)  # Reuse existing function

        print("--------------------------------------")
        print("Available regions:")
        for region in regions:
            print(region)
        print("--------------------------------------")

        selected_regions = input("Select regions to scan (comma separated): ")
        if not selected_regions:
            return False

        selected_regions = [region.strip().lower() for region in selected_regions.replace(' ', '').split(',')]
        for region in selected_regions:
            if region.strip().lower() not in regions:
                print(f"Region {region} is not valid. Skipping...")  # Don't exit, just skip. Best practices.
                selected_regions.remove(region)

        # Convert back to comma separated string
        return ','.join(selected_regions)
