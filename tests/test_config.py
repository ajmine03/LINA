import platform
from config import BASE_DIR, CURRENT_OS, DEFAULT_MODEL, MAX_AGENT_STEPS, OLLAMA_HOST, RUNS_DIR


def test_config_paths():
    assert BASE_DIR.exists()
    assert RUNS_DIR.exists()


def test_config_defaults():
    assert OLLAMA_HOST.startswith("http")
    assert isinstance(DEFAULT_MODEL, str)
    assert MAX_AGENT_STEPS > 0
    assert CURRENT_OS == platform.system()
