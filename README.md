# Password Security Lab

CSCI369 Ethical Hacking — Project

## Requirements

- Kali Linux (or any Debian-based Linux)
- Python 3.11+
- `hashcat` and/or `john` installed:

```bash
sudo apt update && sudo apt install -y hashcat john
```

## Installation

```bash
git clone https://github.com/s91trbnk/Password-cracker
cd Password-cracker

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Setup

1. Run the app:
   ```bash
   streamlit run main.py
   ```
```
```
## Modules

| Module | File | Description |
|--------|------|-------------|
| Strength Analyzer | `app/strength.py` | Entropy calculation and complexity scoring |
| Hash Generator | `app/hashing.py` | Generate MD5/SHA1/SHA256/NTLM/sha512crypt hash files |
| Dictionary Attack | `app/cracker.py` | Wraps hashcat and John the Ripper |
| UI | `app/ui.py` | Streamlit pages |
```
```
## Ethical Use

All testing must be performed in an isolated lab environment (VirtualBox/VMware with internal NAT). Do not use this tool against any public or production systems.
```
