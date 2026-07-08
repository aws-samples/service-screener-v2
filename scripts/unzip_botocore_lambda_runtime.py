import os
import sys
import gzip
import shutil

python_ver = f"{sys.version_info.major}.{sys.version_info.minor}"

if os.path.isdir(os.getcwd() + '/../lib/'):
    lambda_runtime_file_path = os.getcwd() + f"/../lib/python{python_ver}/site-packages/botocore/data/lambda/2015-03-31/service-2.json"
else:    
    lambda_runtime_file_path = os.getcwd() + f"/../lib64/python{python_ver}/site-packages/botocore/data/lambda/2015-03-31/service-2.json"

if not os.path.isfile(lambda_runtime_file_path):
    if os.path.isfile(lambda_runtime_file_path + '.gz'):
        with gzip.open(lambda_runtime_file_path + '.gz', 'rb') as f_in:
            with open(lambda_runtime_file_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
    else:
        print("Lambda Runtime file not found.")

