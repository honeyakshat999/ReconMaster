export FLASK_APP=".\app\__init__.py"
flask db init
flask db migrate
flask db upgrade