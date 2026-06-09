python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn jinja2
uvicorn app:app --host 0.0.0.0 --port 80 --reload
