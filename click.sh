pip3 install virtualenv
python3 -m virtualenv venv
source venv/bin/activate
pip3 install -r .\requirements.txt
export FLASK_APP=".\app\__init__.py"
flask db init
flask db migrate
flask db upgrade