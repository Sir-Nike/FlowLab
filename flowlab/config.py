import os
from pathlib import Path

ROOT = Path(os.environ.get("FLOWLAB_HOME", Path(__file__).resolve().parents[1])).resolve()
DATA = ROOT / "data"
MODELS = ROOT / "models"
RESULTS = ROOT / "results"
for folder in (DATA, MODELS, RESULTS, DATA / "captures"):
    folder.mkdir(parents=True, exist_ok=True)
