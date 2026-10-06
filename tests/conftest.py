from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def isolate_services(monkeypatch, tmp_path):
    # Offline tests must never consume a real service key or write to user scan history.
    for name in ('GROQ_API_KEY','OPENAI_API_KEY','VIRUSTOTAL_API_KEY','SAFE_BROWSING_API_KEY',
                 'DATABASE_URL','POSTGRES_URL','MONGODB_URI','MONGO_URI','OLLAMA_MODEL'):
        monkeypatch.setenv(name, '')
    monkeypatch.setenv('AI_PROVIDER','none')
    monkeypatch.setenv('LOCAL_DB_PATH',str(tmp_path/'test-only.sqlite3'))
