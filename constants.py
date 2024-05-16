import pathlib
import sys

ROOT_DIR = str(pathlib.Path.cwd())

SERVICE_DIR = ROOT_DIR + '/services'
TEMPLATE_DIR = ROOT_DIR + '/templates'
# VENDOR_DIR = ROOT_DIR + '/vendor'
FRAMEWORK_DIR = ROOT_DIR + '/frameworks'
BOTOCORE_DIR = ROOT_DIR + '/../lib64/python'+ str(sys.version_info.major) + '.' + str(sys.version_info.minor) +'/site-packages/botocore'

HTML_FOLDER =  '/adminlte/aws/res'
ADMINLTE_ROOT_DIR = ROOT_DIR + '/adminlte'
ADMINLTE_DIR = ADMINLTE_ROOT_DIR + '/aws'
HTMLRES_DIR = ROOT_DIR + '/' + HTML_FOLDER
FORK_DIR = ROOT_DIR + '/__fork'
API_JSON = FORK_DIR + '/api.json'

GENERAL_CONF_PATH = SERVICE_DIR + '/general.reporter.json'

CLI_TRUE_KEYWORD_ARRAY = ['yes', 'y', 'true', '1', 1]

SESSUID_FILENAME = 'sess-uuid'