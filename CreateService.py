import os
import shutil
import boto3
import argparse
import constants as _C


session = boto3.Session()
services = session.get_available_services()

parser = argparse.ArgumentParser(prog='Create New Checks', description='Clone folders and files for new checks')
parser.add_argument('-s', '--service', required=True, choices=services)
args = parser.parse_args()

serviceName = args.service
serviceName = serviceName.replace("-","")

servicePath = _C.SERVICE_DIR + '/' + serviceName + '/'

if os.path.isdir(servicePath):
    print(servicePath + ' is existing. Please make sure the service name is correct')
else:
    os.mkdir(servicePath)
    os.mkdir(servicePath + 'drivers/')
    
    serviceTemplatePath = os.getcwd() + '/utils/services-template/'
    
    if not os.path.isdir(serviceTemplatePath):
        print("Service template is missing. Please reach out to service screener team for further support")
    else:
        shutil.copyfile(serviceTemplatePath + 'Service.py', servicePath + serviceName.capitalize() + '.py')
        shutil.copyfile(serviceTemplatePath + 'service.reporter.json', servicePath + serviceName + '.reporter.json')
        shutil.copyfile(serviceTemplatePath + 'drivers/ServiceDriver.py', servicePath + 'drivers/' + serviceName.capitalize() + 'Common.py')