# Clippy-for-MITRE
Created to help me quickly get information on Enterprise MITRE tactics

## Simple MITRE Agent Bot

This repo now includes a local CLI bot that lets you ask questions about MITRE ATT&CK Enterprise data.

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
python mitre_agent.py --data enterprise-attack-v18.1.xlsx
```

You can also point it at a CSV file:

```bash
python mitre_agent.py --data your-file.csv
```

### Example Questions

- What is T1059?
- Credential access tactics
- APT29 software
- What mitigations exist for phishing?

Type `exit` to quit.
