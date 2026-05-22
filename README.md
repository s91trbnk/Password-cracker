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

1. Run the app — a bundled wordlist (`wordlists/common.txt`) is included so no extra setup is needed:
   ```bash
   streamlit run main.py
   ```

2. *(Optional)* For deeper cracking, add rockyou.txt to `wordlists/`:
   ```bash
   sudo gunzip /usr/share/wordlists/rockyou.txt.gz   # only needed once
   cp /usr/share/wordlists/rockyou.txt wordlists/
   ```
```
>>>>>>> ae14fcc3156ee808c7cac234c54b0b4356c49f64
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
