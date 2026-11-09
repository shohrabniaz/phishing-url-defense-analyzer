from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.analyser import analyse_csv

def test_flags_lookalikes():
    res = analyse_csv(ROOT / "data" / "urls.csv")
    assert res["high"] >= 1
    assert any("lookalike" in ",".join(r["reasons"]) or r["score"] >= 50 for r in res["results"])

if __name__ == "__main__":
    test_flags_lookalikes(); print("smoke_ok")
