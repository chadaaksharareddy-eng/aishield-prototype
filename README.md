# AIShield Advanced Starter

A local Streamlit hackathon prototype demonstrating explainable, rule-based AI data-leakage checks.

## Files
- `app.py` — interactive dashboard and demo scenarios
- `scanner.py` — scanner rules and allow/warn/block decision logic
- `tests/test_scanner.py` — automated unit tests
- `requirements.txt` — Python dependencies

## Windows PowerShell setup
Open PowerShell in this folder, then run:

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If `py` is unavailable but `python --version` works, use `python -m venv .venv` instead.

## Demo scenarios
- Safe project update → ALLOW
- API-key-shaped synthetic string → BLOCK
- Demo email address → WARN
- Instruction-override phrase → BLOCK

## Safety and scope
Use synthetic data only. This is not a production DLP system. It scans only text entered in this interface, does not intercept other applications, and uses simple pattern matching that can miss risks or flag harmless text.
