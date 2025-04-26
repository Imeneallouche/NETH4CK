# NETH4CK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)  
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-orange)](https://flask.palletsprojects.com/)
---

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Contributing](#contributing)
8. [License](#license)
9. [References](#references)
10. [Contact](#contact)

---

## Introduction

NETH4CK is a portable, web-based network auditing and penetration testing tool built on a Raspberry Pi. It automates internal reconnaissance and key attack techniques—LLMNR, mDNS, NetBIOS poisonings, WPAD rogue proxy, passive network analysis, credential harvesting, and more—through a user-friendly Flask interface.

Originally a terminal script for Responder modules, NETH4CK integrates multiple functionalities into a cohesive, accessible platform suitable for red teams and security auditors.

---

## Features

- **LLMNR, mDNS & NBT-NS Poisoning**: Automate name-resolution poisoning attacks to capture credentials.
- **WPAD Rogue Proxy**: Exploit WPAD configuration to perform man-in-the-middle attacks.
- **Passive Network Analysis**: Monitor network traffic without active probing.
- **Network Interface & IP Control**: Switch interfaces, assign addresses, and scan subnets easily.
- **Weak Hash Testing**: Identify systems using weak hashing algorithms.
- **Host Fingerprinting**: Gather OS and client version details via SMB fingerprinting.
- **Web-Based Dashboard**: Real-time display of outputs and controls in Flask-powered pages.
- **Portable & Lightweight**: Runs on Raspberry Pi for field-friendly deployments.

---

## Architecture

```
+-------------------+      +---------------------+      +----------------+
|      Client       | <--> |     Raspberry Pi    | <--> |   Target LAN    |
| (Browser/Flask UI)|      | (NETH4CK Backend)   |      | (Victim Hosts)  |
+-------------------+      +---------------------+      +----------------+
```

- **Backend**: Python 3, Flask, custom modules for each poisoning/analysis.
- **Frontend**: HTML/CSS, Jinja2 templates styled as interactive controls and terminal emulation.
- **Utilities**: `utils.py` for parsing, IP/subnet helpers; `packets/` for custom packet crafting.
- **Fingerprinting**: SMB fingerprint via `fingerprint` module.

---

## Installation

1. **Prepare Raspberry Pi**:

   - Raspberry Pi OS (32-bit) or compatible Linux.
   - Python 3.8+ installed.

2. **Clone Repository**:

   ```bash
   git clone https://github.com/<your-org>/NETH4CK.git
   cd NETH4CK
   ```

3. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Enable IP Forwarding** (if needed):

   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

---

## Configuration

- ``: Edit bind address, analysis vs. poisoning modes, enabled modules.
- ``: Ensure correct nameservers for ICMP redirect analysis.

Example:

```python
Config = {
    'Bind_To': '192.168.1.100',
    'AnalyzeMode': False,
    'Finger_On_Off': True,
    'NBTNSDomain': True,
    'Wredirect': False,
}
```

---

## Usage

1. **Start the Flask App**:
   ```bash
   python app.py
   ```
2. **Access Dashboard**: Open `http://<Pi_IP>:5000` in your browser.
3. **Select Modules**: Choose poisoning or analysis modules from the UI and view real-time results.
4. **Stop Services**: Use the provided controls to stop background sniffers or poisoning loops.

---

## Contributing

Contributions are welcome:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/YourFeature`.
3. Commit changes: `git commit -m "Add YourFeature"`.
4. Push to branch: `git push origin feature/YourFeature`.
5. Open a Pull Request.

Please follow the existing code style and include tests where applicable.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## References

1. Intigriti. (2024). *Pentesting network*. In HackTricks. Retrieved from [https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network)
2. Responder GitHub repository. (2024). *Responder: An LLMNR, NBT-NS, and MDNS poisoner*. Retrieved from [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

---

## Contact

**Imène ALLOUCHE**\
4th-year Cybersecurity Student & Instructor at Code Labs Academy\
Email: [li_allouche@esi.dz](mailto\:li_allouche@esi.dz)

