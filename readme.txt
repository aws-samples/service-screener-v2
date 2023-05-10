## First installation
python -m venv .
source bin/activate
git clone https://github.com/kuettai/ss-poc.git
mv ss-poc src
cd src
pip install -e .
pip install boto3
pip install packaging
pip install xlsxwriter

## Future re-run
cd <folder>
source bin/activate
cd src
pip install -e .
