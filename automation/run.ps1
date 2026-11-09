Set-Location (Split-Path -Parent $PSScriptRoot)
python -m src.cli analyse --path .\data\urls.csv
python tests\test_smoke.py
