# Password Security Lab

CSCI369 Ethical Hacking — Password Cracking Tool

## Requirements

- Kali Linux
- Python 3.11+
- hashcat, john, hydra:

```bash
sudo apt update && sudo apt install -y hashcat john hydra
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

<<<<<<< HEAD
1. Run the app — a bundled wordlist (`wordlists/common.txt`) is included:
=======
1. Run the app — a bundled wordlist (`wordlists/common.txt`) is included so no extra setup is needed:
>>>>>>> 0833198bcc7064dc4940bfb5beb715be46759232
   ```bash
   streamlit run main.py
   ```

2. *(Recommended)* Add rockyou.txt for full cracking power:
   ```bash
   sudo gunzip /usr/share/wordlists/rockyou.txt.gz
   cp /usr/share/wordlists/rockyou.txt wordlists/
   ```
<<<<<<< HEAD

## Attack Modules
=======
```
## Modules
>>>>>>> 0833198bcc7064dc4940bfb5beb715be46759232

| Module | Type | Description |
|--------|------|-------------|
| Dictionary Attack | Offline | Wordlist vs hash file — best with rockyou.txt |
| Brute Force Attack | Offline | Every character combination up to N length |
| Hybrid Attack | Offline | Wordlist + mutations (mask or hashcat rules) |
| Online Attack | Online | Hydra against live SSH/FTP on Metasploitable VM |

## Lab Setup (Online Attack)

For the Online Attack module you need:
- Metasploitable 2 VM running in VirtualBox (internal NAT network)
- Note its IP: `ip addr` on the Metasploitable terminal
- Enter that IP in the Online Attack page, select SSH or FTP

## Ethical Use

All attacks must target student-built VMs in a local, isolated lab.
Do not use this tool against any public or production systems.
