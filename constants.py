import pathlib

ROOT_DIR = str(pathlib.Path.cwd())

SERVICE_DIR = ROOT_DIR + '/services'
TEMPLATE_DIR = ROOT_DIR + '/templates'
# VENDOR_DIR = ROOT_DIR + '/vendor'
FRAMEWORK_DIR = ROOT_DIR + '/frameworks'
BOTOCORE_DIR = ROOT_DIR + '/../lib64/python3.7/site-packages/botocore'

HTML_FOLDER =  '/adminlte/html'
HTML_DIR = ROOT_DIR + '/' + HTML_FOLDER
FORK_DIR = ROOT_DIR + '/__fork'
API_JSON = FORK_DIR + '/api.json'

GENERAL_CONF_PATH = SERVICE_DIR + '/general.reporter.json'

CLI_TRUE_KEYWORD_ARRAY = ['yes', 'y', 'true', '1', 1]

SESSUID_FILENAME = 'sess-uuid'