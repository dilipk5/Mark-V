# AD Pentest Assistant

A lightweight Python-based Active Directory penetration testing assistant designed to automate common enumeration tasks.

The tool bootstraps a target using `nxc smb` to identify the hostname, domain, OS, and SMB signing status, then provides simple modules for SMB enumeration, credential checks, user enumeration, and BloodHound data collection.

## Features

- Automatic target/domain discovery with `nxc smb`
- SMB null-session and guest enumeration
- Credential validation and user enumeration
- BloodHound collection using NetExec
- BloodHound collection using RustHound-CE
- Simple task-based architecture

## Tasks

| Command | Description |
|---|---|
| `smbnull` | Enumerate anonymous/guest SMB access and shares |
| `getusers` | Validate credentials and export domain users |
| `nxcbloodhound` | Collect BloodHound data using NetExec |
| `rusthound` | Collect BloodHound data using RustHound-CE |

## Requirements

- Python 3
- NetExec (`nxc`)
- RustHound-CE
- Valid AD target/lab

## Usage

```bash
python3 main.py -t <target-ip>
