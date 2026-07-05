# UGREEN Inspector

**Browser-based security audit tool for UGREEN UGOS configuration backups.**

UGREEN Inspector analyses `.ugb` backup files exported from UGREEN NAS devices running UGOS and checks your NAS configuration against security best practices and common compliance frameworks — entirely in your browser, with no data ever leaving your device.

---

## Features

- **Security checks** across Remote Access, Protocols, and Network Security
- **Best Practices checks** for file services, firmware updates, and SMB configuration
- **Framework references** — CIS Controls, NIST SP 800-53, ISO 27001, NIS2
- **Security score** with letter grade (A–F) and verdict
- **Filter by severity** — Critical, High, Medium, Low
- **EN / DE** — full English and German UI
- **100% client-side** — no server, no telemetry, no internet connection required
- **Source available** — every line of code is open to inspection before use

## Members

YouTube channel members receive an extended version with **PDF export** — a branded, print-ready security assessment report.

→ [youtube.com/@navigio1](https://www.youtube.com/@navigio1)

---

## How to Use

1. **Download** the latest release ZIP and unpack it
2. **Open** `index.html` in your browser (works from `file://` — no web server needed)
3. **Drop** your `.ugb` backup file onto the upload area
4. **Review** the findings

### Exporting a UGREEN UGOS backup

In the UGOS web interface: **Control Panel → Update & Restore → Configuration Backup & Restore → Local Backup**

Auf Deutsch: **Systemsteuerung → Aktualisieren & Wiederherstellen → Sichern & Wiederherstellen von Konfiguration → Lokale Sicherung**

The exported file has a `.ugb` extension.

---

## Privacy

Your backup file is processed entirely within your browser using client-side JavaScript. No data is transmitted to any server — not even anonymised telemetry. The tool works fully offline.

You are encouraged to review the source code before use.

---

## Supported UGOS Versions

Tested against UGOS Pro. Earlier versions may work if the backup format is compatible.

---

## Security Checks

| Category | Check | Severity |
|---|---|---|
| Remote Access | Telnet enabled | Critical |
| Remote Access | SSH enabled | Medium |
| Remote Access | SSH accessible from WAN | High |
| Protocols | SMBv1 allowed | High |
| Protocols | SMB signing not required | High / Medium |
| Protocols | SMB encryption disabled | Medium |
| Protocols | FTP without TLS | High |
| Protocols | FTP anonymous access enabled | Critical |
| Protocols | WebDAV over HTTP | High |
| Protocols | NFS v3 only (no NFSv4) | Medium |
| Network Security | DoS protection not enabled | Medium |
| User Accounts | Minimum password length below 12 | Medium |
| User Accounts | Common password check disabled | Low |
| User Accounts | Special characters not required | Low |
| User Accounts | Password expiry not configured | Low |

## Best Practice Checks

| Category | Check |
|---|---|
| SMB | Cross-share symlinks (wide links) enabled |
| File Services | FTP service active |
| File Services | Rsync daemon active |
| File Services | NFS service active |
| Maintenance | Firmware auto-install enabled |

---

## License

Source Available — free for personal, non-commercial use.  
Commercial use requires written permission. See [LICENSE](LICENSE) for details.

© 2025–2026 Jürgen Barth, JKLP Consulting

---

## About

**JKLP Consulting** provides security audits, NAS hardening, and IT security advisory for small and medium-sized businesses.

- Website: [jklp.io](https://jklp.io)
- YouTube: [@navigio1](https://www.youtube.com/@navigio1)
- Contact: [contact@jklp.io](mailto:contact@jklp.io)
