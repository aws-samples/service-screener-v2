## First installation
cd /tmp
python -m venv .
source bin/activate
git clone https://github.com/aws-samples/service-screener-v2.git
cd service-screener-v2
pip install -r requirements.txt
alias screener="python3 $(pwd)/main.py"

## Future re-run
cd <folder>
source bin/activate
cd service-screener-v2
pip install -e .
alias screener="python3 $(pwd)/main.py"