# NmapGhost

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Nmap](https://img.shields.io/badge/nmap-latest-green)](https://nmap.org/)
[![License](https://img.shields.io/badge/license-MIT-red)](LICENSE)

Professional Nmap automation tool for **pentesting** and **CTFs**.

<img src="https://i.imgur.com/1rlEMRS.png" alt="NmapGhost Banner" width="600"/>

---

## Quick Installation

### Linux (Debian / Ubuntu / Kali)

```bash
# Update packages and install dependencies
sudo apt update
sudo apt install -y nmap python3 python3-pip git

# Clone repository and install tool
git clone https://github.com/cenidev/nmapghost.git
cd nmapghost
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Run
nmapghost
````

### Arch Linux

```bash
sudo pacman -Syu
sudo pacman -S nmap python python-pip git

git clone https://github.com/cenidev/nmapghost.git
cd nmapghost
python3 -m venv venv
source venv/bin/activate
pip install -e .

nmapghost
```

### Fedora

```bash
sudo dnf install -y nmap python3 python3-pip git

git clone https://github.com/cenidev/nmapghost.git
cd nmapghost
python3 -m venv venv
source venv/bin/activate
pip install -e .

nmapghost
```

### macOS (Homebrew)

```bash
brew update
brew install nmap python git

git clone https://github.com/cenidev/nmapghost.git
cd nmapghost
python3 -m venv venv
source venv/bin/activate
pip install -e .

nmapghost
```

### Windows (PowerShell)

1. Install [Python](https://www.python.org/) — check **Add to PATH**.
2. Install [Nmap](https://nmap.org/download) — run as administrator.

```powershell
git clone https://github.com/cenidev/nmapghost.git
cd nmapghost
python -m venv venv
venv\Scripts\Activate.ps1    # PowerShell
# Or for CMD: venv\Scripts\activate.bat
pip install -e .

nmapghost
```

> ⚠️ If you have both `python` and `python3`, use the command that works in your environment.

---

## Alternative Execution (Without `pip install -e .`)

```bash
git clone https://github.com/cenidev/nmapghost.git
cd nmapghost
pip install -r requirements.txt
python main.py
```

---

## Verify Installation

```bash
nmap --version
python --version    # or python3 --version
nmapghost            # or: python main.py
```

---

## ⚠️ Disclaimer

NmapGhost is provided **“as-is”**. The author is **not responsible** for any damage, misuse, legal issues, or security incidents that may occur from using this software. Use it **at your own risk**. This tool is intended for **educational and ethical pentesting purposes only**.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.