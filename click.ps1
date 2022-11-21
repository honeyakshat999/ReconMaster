python -m venv venv
.\venv\Scripts\activate
pip install -r .\requirements.txt
$Env:FLASK_APP=".\app\__init__.py"
flask db init
flask db migrate
flask db upgrade