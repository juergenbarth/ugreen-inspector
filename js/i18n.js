/**
 * i18n.js — internationalisation for UGREEN Inspector
 *
 * Usage:
 *   t('key')           — returns the translated string for the active language
 *   setLanguage('de')  — switches to German (persisted in localStorage)
 *
 * Languages: 'en' (default), 'de'
 */

(function () {
    'use strict';

    const STRINGS = {
        en: {
            // ── UI chrome ────────────────────────────────────────────────────
            appTitle:        'UGREEN Inspector',
            appVersion:      'v1.0',
            appSubtitle:     'JKLP CONSULTING · SECURITY AUDIT',

            // ── Drop zone ────────────────────────────────────────────────────
            dropTitle:       'Drop your UGREEN .ugb backup here',
            dropOr:          'or',
            dropBrowse:      'browse for file',
            dropFormats:     'Supported: UGREEN UGOS configuration backup (.ugb)',
            dropPrivacy:     'This file is processed entirely in your browser. Nothing is sent to any server.',

            // ── States ────────────────────────────────────────────────────────
            loading:         'Analysing backup…',
            loadingHint:     'Decompressing and parsing — this may take a few seconds.',
            btnNewFile:      'Analyse another file',

            // ── Errors ────────────────────────────────────────────────────────
            errFileRead:     'Could not read file',
            errParse:        'Failed to parse backup (is this a valid .ugb file?)',
            errUnknown:      'An unexpected error occurred',

            // ── Context bar ────────────────────────────────────────────────────
            labelFileName:      'File',
            labelFileSize:      'Size',
            labelUGOSVersion:   'UGOS',
            labelHostname:      'Hostname',
            labelSerialNumber:  'Serial',

            // ── Compliance view ────────────────────────────────────────────────
            complianceTitle:     'Security Assessment',
            labelAffected:       'Affected',
            labelRemediation:    'Remediation',

            // ── Severity labels ────────────────────────────────────────────────
            severityCritical:    'Critical',
            severityHigh:        'High',
            severityMedium:      'Medium',
            severityLow:         'Low',
            severityInfo:        'Info',

            // ── Verdicts ──────────────────────────────────────────────────────
            verdictStrong:       'Strong Security Posture',
            verdictGood:         'Good Security Posture',
            verdictAcceptable:   'Acceptable — Improvements Recommended',
            verdictImprove:      'Needs Improvement',
            verdictExposure:     'Significant Exposure',
            verdictCritical:     'Critical — Immediate Action Required',

            // ── Tab bar ───────────────────────────────────────────────────────
            tabSecurity:         'Security Check',
            tabBestPractices:    'Best Practices',

            // ── Best Practices view ───────────────────────────────────────────
            bpViewTitle:         'Best Practices Assessment',
            bpNoIssuesTitle:     'All Best-Practice Checks Passed',
            bpNoIssuesSub:       'Your configuration follows all recommended best practices.',

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Remote Access',
            catProtocols:        'Protocols & File Sharing',
            catUsers:            'User Accounts',
            catMaintenance:      'Maintenance',
            catNetwork:          'Network Security',
            catBPSMB:            'SMB',
            catBPFileServices:   'File Services',

            // ── Common ────────────────────────────────────────────────────────
            affectedAllInterfaces: 'All network interfaces',
            affectedAllUsers:      'All user accounts',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkTelnetFailTitle:    'Telnet Is Enabled',
            checkTelnetPassTitle:    'Telnet Is Disabled',
            checkTelnetDesc:         'Telnet transmits all data — including credentials — in plain text. Any network observer or man-in-the-middle can intercept passwords and session content. Telnet has been superseded by SSH for all remote shell access.',
            checkTelnetRemediation:  'Disable Telnet in UGOS Control Panel › Terminal.',

            checkSSHFailTitle:       'SSH Is Enabled',
            checkSSHPassTitle:       'SSH Is Disabled',
            checkSSHDesc:            'SSH exposes a remote shell to the NAS over the network. If not actively required, SSH should be disabled to minimise attack surface. If SSH is needed, restrict access to trusted source addresses and enforce key-based authentication.',
            checkSSHRemediation:     'Disable SSH if not required: UGOS Control Panel › Terminal. If SSH is needed, restrict access to LAN only.',

            checkSSHLanOnlyFailTitle: 'SSH Is Accessible from the Internet (WAN)',
            checkSSHLanOnlyPassTitle: 'SSH Access Is Restricted to LAN',
            checkSSHLanOnlyDesc:      'SSH is enabled and accessible from outside the local network. This exposes the remote shell interface to the public internet, significantly increasing the risk of brute-force attacks, exploitation of SSH vulnerabilities, and unauthorized access.',
            checkSSHLanOnlyRemediation: 'Restrict SSH to LAN only: UGOS Control Panel › Terminal › SSH › Permit LAN access only.',

            // ── check-filesharing.js ───────────────────────────────────────────
            checkSMB1FailTitle:      'SMBv1 Is Allowed',
            checkSMB1PassTitle:      'SMBv1 Is Disabled',
            checkSMB1Desc:           'SMBv1 is a legacy protocol with no encryption, no integrity checking, and no modern authentication. It is the vector for EternalBlue (WannaCry, NotPetya) and numerous other critical exploits. All modern clients support SMB2 or SMB3.',
            checkSMB1Remediation:    'Set the minimum SMB protocol to SMB2 or higher: UGOS Control Panel › File Services › SMB.',

            checkSMBSigningFailTitle: 'SMB Signing Is Not Enforced',
            checkSMBSigningPassTitle: 'SMB Signing Is Required',
            checkSMBSigningDesc:      'SMB signing ensures that network packets have not been tampered with in transit. Without it, the NAS is vulnerable to NTLM relay attacks and man-in-the-middle attacks against SMB connections. "If required" mode is not sufficient — signing must be set to Required.',
            checkSMBSigningRemediation: 'Set SMB signing to Required: UGOS Control Panel › File Services › SMB › Server Signing Mode.',

            checkSMBEncryptFailTitle: 'SMB Encryption Is Disabled',
            checkSMBEncryptPassTitle: 'SMB Encryption Is Enabled',
            checkSMBEncryptDesc:      'Without SMB encryption, file content and credentials transmitted over SMB connections can be intercepted by anyone on the network path. SMB encryption (SMB3 feature) protects data in transit between the NAS and clients.',
            checkSMBEncryptRemediation: 'Enable SMB encryption: UGOS Control Panel › File Services › SMB › Encryption Mode (set to "Desired" or "Required").',

            checkFTPTLSFailTitle:    'Plain FTP Is Enabled',
            checkFTPTLSPassTitle:    'Plain FTP Is Disabled',
            checkFTPTLSDesc:         'Plain FTP transmits credentials and file content in clear text. Anyone on the network path can intercept passwords and data. Use FTPS (FTP over TLS) or switch to SFTP instead.',
            checkFTPTLSRemediation:  'Disable plain FTP and enable FTPS only: UGOS Control Panel › File Services › FTP.',

            checkFTPAnonFailTitle:   'FTP Anonymous Access Is Enabled',
            checkFTPAnonDesc:        'Anonymous FTP allows any user to connect without credentials. This exposes shared files to the network without authentication.',
            checkFTPAnonRemediation: 'Disable anonymous FTP access: UGOS Control Panel › File Services › FTP.',

            checkWebDAVHttpFailTitle: 'WebDAV Is Accessible over HTTP',
            checkWebDAVHttpPassTitle: 'WebDAV Is HTTPS-Only',
            checkWebDAVHttpDesc:      'WebDAV over unencrypted HTTP transmits credentials and file content in plain text. Any network observer can intercept authentication tokens and file data.',
            checkWebDAVHttpRemediation: 'Disable HTTP WebDAV and use HTTPS only: UGOS Control Panel › File Services › WebDAV.',

            checkNFSV3FailTitle:     'NFS Is Running with NFSv3 Only',
            checkNFSV4PassTitle:     'NFS Is Configured for NFSv4',
            checkNFSV3Desc:          'NFSv3 lacks authentication mechanisms beyond IP-address-based access controls. Any host that can reach the NAS on the network can potentially access NFS exports. NFSv4 supports Kerberos-based authentication and provides significantly stronger access control.',
            checkNFSV3Remediation:   'Enable NFSv4 support: UGOS Control Panel › File Services › NFS › Maximum NFS Protocol.',

            // ── check-network.js ───────────────────────────────────────────────
            checkDoSFailTitle:       'DoS Protection Is Disabled',
            checkDoSPassTitle:       'DoS Protection Is Active',
            checkDoSDesc:            'DoS (Denial of Service) protection drops malformed and flood packets before they can exhaust system resources. Without it, even simple network floods can degrade NAS responsiveness for legitimate users.',
            checkDoSRemediation:     'Enable DoS protection: UGOS Control Panel › Security › Firewall › DoS Protection.',

            // ── check-users.js ─────────────────────────────────────────────────
            checkPwdLengthFailTitle: 'Minimum Password Length Is Below Recommended Threshold',
            checkPwdLengthPassTitle: 'Minimum Password Length Meets Recommended Threshold',
            checkPwdLengthDesc:      'The current minimum password length ({0} characters) is below the recommended minimum of 12. Short passwords are significantly easier to crack by brute-force or dictionary attacks.',
            checkPwdLengthRemediation: 'Increase the minimum password length to at least 12 characters: UGOS Control Panel › Users › Password Policy.',

            checkPwdCommonFailTitle: 'Common Password Check Is Not Enabled',
            checkPwdCommonPassTitle: 'Common Password Check Is Active',
            checkPwdCommonDesc:      'Without a common password check, users may set easily-guessable passwords such as "Password1!" that technically meet complexity rules but offer minimal real-world security.',
            checkPwdCommonRemediation: 'Enable common password check: UGOS Control Panel › Users › Password Policy.',

            checkPwdSpecialFailTitle: 'Password Policy Does Not Require Special Characters',
            checkPwdSpecialPassTitle: 'Password Policy Requires Special Characters',
            checkPwdSpecialDesc:      'Requiring at least one special character significantly increases password entropy and resistance to dictionary attacks.',
            checkPwdSpecialRemediation: 'Enable special character requirement: UGOS Control Panel › Users › Password Policy.',

            checkPwdExpiryFailTitle: 'Password Expiry Is Not Enforced',
            checkPwdExpiryPassTitle: 'Password Expiry Is Enforced',
            checkPwdExpiryDesc:      'Without password expiry, compromised credentials remain valid indefinitely. Enforcing a maximum password age limits the window of exposure if a password is leaked.',
            checkPwdExpiryRemediation: 'Enable password expiry: UGOS Control Panel › Users › Password Expiry.',

            // ── check-maintenance.js ───────────────────────────────────────────
            checkAutoUpdateFailTitle: 'Automatic Firmware Updates Are Disabled',
            checkAutoUpdatePassTitle: 'Automatic Firmware Updates Are Enabled',
            checkAutoUpdateDesc:      'With automatic updates disabled, security patches must be applied manually. Delayed patching leaves the NAS exposed to known vulnerabilities for longer than necessary.',
            checkAutoUpdateRemediation: 'Enable automatic firmware updates: UGOS Control Panel › System Update › Automatic Update.',

            // ── check-bestpractices.js ─────────────────────────────────────────
            bpCheckWideLinksFailTitle: 'SMB Wide Links Are Enabled',
            bpCheckWideLinksPassTitle: 'SMB Wide Links Are Disabled',
            bpCheckWideLinksDesc:      'Wide links allow symbolic links inside a share to point to paths outside that share, including other shares or the host filesystem. This can unintentionally expose data to SMB users outside their intended scope.',
            bpCheckWideLinksRemediation: 'Disable wide links: UGOS Control Panel › File Services › SMB › Advanced.',

            bpCheckFTPActiveFailTitle: 'FTP Service Is Running',
            bpCheckFTPActivePassTitle: 'FTP Service Is Disabled',
            bpCheckFTPActiveDesc:      'The FTP service is running. Even if plain FTP is disabled and only FTPS is active, every running service increases the attack surface. Consider disabling FTP entirely and using SFTP (over SSH) if remote file transfer is required.',
            bpCheckFTPActiveRemediation: 'Disable the FTP service entirely if not required: UGOS Control Panel › File Services › FTP.',

            bpCheckRsyncActiveFailTitle: 'Rsync Daemon Is Running',
            bpCheckRsyncActivePassTitle: 'Rsync Daemon Is Disabled',
            bpCheckRsyncActiveDesc:      'The Rsync daemon exposes a network file-sync service. If not actively used for backups or replication, it should be disabled to reduce the attack surface.',
            bpCheckRsyncActiveRemediation: 'Disable Rsync if not required: UGOS Control Panel › File Services › Rsync.',

            bpCheckNFSActiveFailTitle: 'NFS Service Is Running',
            bpCheckNFSActivePassTitle: 'NFS Service Is Disabled',
            bpCheckNFSActiveDesc:      'NFS is a legacy network file system protocol originally designed for trusted internal networks. It provides no per-user authentication at the transport level and relies solely on IP-based access controls. Disable NFS if clients can use SMB instead.',
            bpCheckNFSActiveRemediation: 'Disable NFS if not required: UGOS Control Panel › File Services › NFS.',

            // ── Compliance view UI ─────────────────────────────────────────────
            frameworksLabel:         'Frameworks',
            clearFiltersBtn:         'Clear',
            clearAllFiltersBtn:      'Clear all filters',
            findingPlural:           'issues',
            findingSingular:         'issue',
            filteredBy:              'filtered by',
            ofTotal:                 'of',
            noFindingsTitle:         'No Issues Found',
            noFindingsSub:           'All security checks passed.',
            issueCount:              '1 issue',
            issuesCount:             '{0} issues',
            severityPass:            'Pass',
            passedChecks:            'Passed checks',

            // ── Excluded checks section ────────────────────────────────────────
            excludedChecksTitle: 'Deliberately Excluded Checks',
            excludedChecksDesc:  'UGREEN Inspector intentionally omits recommendations to move services to non-standard port numbers — such as changing SSH away from port 22 or management interfaces away from their default ports. This is Security by Obscurity: it does not reduce the attack surface, adds operational overhead, and creates a false sense of security. Any port scanner finds a service regardless of which port it runs on.',

            // ── About ──────────────────────────────────────────────────────────
            aboutBtn:         'About this tool',
            aboutMaker:       'JKLP CONSULTING · SECURITY AUDIT',
            aboutDesc:        'UGREEN Inspector analyses UGREEN UGOS configuration backups (.ugb) directly in your browser — no data is ever uploaded. It checks your NAS configuration against security best practices and common compliance frameworks.',
            aboutSoBNote:     'Inspector deliberately excludes "Security by Obscurity" checks — such as recommendations to change default port numbers. These add operational overhead without providing real security.',
            aboutChannelName: 'JKLP Consulting',
            aboutChannelDesc: 'Security audits, NAS hardening guides, and IT security for SMEs.',
            aboutWebsiteName: 'jklp.io',
            aboutWebsiteDesc: 'Book a security consultation',
            aboutBadgeFree:   'Free for personal use',
            aboutBadgeOS:     'Source available',
            aboutBadgePrivacy:'No data leaves your browser',

            // ── Disclaimer ─────────────────────────────────────────────────────
            disclaimerTitle:  'Important Notice',
            disclaimerItem1:  'This tool provides automated analysis as technical guidance only and does not replace a professional security audit.',
            disclaimerItem2:  'It makes no claim to completeness or correctness.',
            disclaimerItem3:  'Results serve as technical orientation only and do not constitute professional security advice.',
            disclaimerItem4:  'The mapping to compliance frameworks is for technical orientation only and does not constitute certification or legal assessment.',
            disclaimerItem5:  'The tool analyses backups in read-only mode and makes no changes to your UGREEN NAS.',
            disclaimerFooter: 'Use at your own risk.',
        },

        de: {
            // ── UI chrome ────────────────────────────────────────────────────
            appTitle:        'UGREEN Inspector',
            appVersion:      'v1.0',
            appSubtitle:     'JKLP CONSULTING · SICHERHEITSAUDIT',

            // ── Drop zone ────────────────────────────────────────────────────
            dropTitle:       'UGREEN .ugb-Backup hier ablegen',
            dropOr:          'oder',
            dropBrowse:      'Datei auswählen',
            dropFormats:     'Unterstützt: UGREEN UGOS Konfigurationssicherung (.ugb)',
            dropPrivacy:     'Die Datei wird ausschließlich im Browser verarbeitet. Es werden keine Daten an einen Server übertragen.',

            // ── States ────────────────────────────────────────────────────────
            loading:         'Backup wird analysiert…',
            loadingHint:     'Dekomprimierung und Analyse — dies kann einige Sekunden dauern.',
            btnNewFile:      'Weitere Datei analysieren',

            // ── Errors ────────────────────────────────────────────────────────
            errFileRead:     'Datei konnte nicht gelesen werden',
            errParse:        'Backup konnte nicht analysiert werden (ist dies eine gültige .ugb-Datei?)',
            errUnknown:      'Ein unerwarteter Fehler ist aufgetreten',

            // ── Context bar ────────────────────────────────────────────────────
            labelFileName:      'Datei',
            labelFileSize:      'Größe',
            labelUGOSVersion:   'UGOS',
            labelHostname:      'Hostname',
            labelSerialNumber:  'Seriennr.',

            // ── Compliance view ────────────────────────────────────────────────
            complianceTitle:     'Sicherheitsbewertung',
            labelAffected:       'Betroffen',
            labelRemediation:    'Behebung',

            // ── Severity labels ────────────────────────────────────────────────
            severityCritical:    'Kritisch',
            severityHigh:        'Hoch',
            severityMedium:      'Mittel',
            severityLow:         'Niedrig',
            severityInfo:        'Info',

            // ── Verdicts ──────────────────────────────────────────────────────
            verdictStrong:       'Starke Sicherheitslage',
            verdictGood:         'Gute Sicherheitslage',
            verdictAcceptable:   'Akzeptabel – Verbesserungen empfohlen',
            verdictImprove:      'Verbesserungsbedarf',
            verdictExposure:     'Erhebliches Risiko',
            verdictCritical:     'Kritisch – Sofortiger Handlungsbedarf',

            // ── Tab bar ───────────────────────────────────────────────────────
            tabSecurity:         'Sicherheitsprüfung',
            tabBestPractices:    'Best Practices',

            // ── Best Practices view ───────────────────────────────────────────
            bpViewTitle:         'Best-Practices-Bewertung',
            bpNoIssuesTitle:     'Alle Best-Practice-Prüfungen bestanden',
            bpNoIssuesSub:       'Ihre Konfiguration entspricht allen empfohlenen Best Practices.',

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Fernzugriff',
            catProtocols:        'Protokolle & Dateidienste',
            catUsers:            'Benutzerkonten',
            catMaintenance:      'Wartung',
            catNetwork:          'Netzwerksicherheit',
            catBPSMB:            'SMB',
            catBPFileServices:   'Dateidienste',

            // ── Common ────────────────────────────────────────────────────────
            affectedAllInterfaces: 'Alle Netzwerkschnittstellen',
            affectedAllUsers:      'Alle Benutzerkonten',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkTelnetFailTitle:    'Telnet ist aktiviert',
            checkTelnetPassTitle:    'Telnet ist deaktiviert',
            checkTelnetDesc:         'Telnet überträgt alle Daten einschließlich Anmeldedaten im Klartext. Jeder Netzwerkbeobachter kann Passwörter und Sitzungsinhalte mitlesen. SSH ist der sichere Ersatz für alle Remote-Shell-Zugriffe.',
            checkTelnetRemediation:  'Telnet deaktivieren: UGOS Systemsteuerung › Terminal.',

            checkSSHFailTitle:       'SSH ist aktiviert',
            checkSSHPassTitle:       'SSH ist deaktiviert',
            checkSSHDesc:            'SSH stellt eine Remote-Kommandozeilenschnittstelle zum NAS bereit. Falls SSH nicht aktiv benötigt wird, sollte es deaktiviert werden, um die Angriffsfläche zu minimieren. Falls SSH erforderlich ist, sollte der Zugriff auf vertrauenswürdige Adressen beschränkt und schlüsselbasierte Authentifizierung erzwungen werden.',
            checkSSHRemediation:     'SSH deaktivieren, wenn nicht benötigt: UGOS Systemsteuerung › Terminal. Falls SSH erforderlich ist, Zugriff auf LAN beschränken.',

            checkSSHLanOnlyFailTitle: 'SSH ist aus dem Internet erreichbar (WAN)',
            checkSSHLanOnlyPassTitle: 'SSH-Zugriff ist auf LAN beschränkt',
            checkSSHLanOnlyDesc:      'SSH ist aktiviert und von außerhalb des lokalen Netzwerks erreichbar. Dies setzt die Remote-Shell dem öffentlichen Internet aus und erhöht das Risiko von Brute-Force-Angriffen, SSH-Exploits und unbefugtem Zugriff erheblich.',
            checkSSHLanOnlyRemediation: 'SSH auf LAN beschränken: UGOS Systemsteuerung › Terminal › SSH › Nur LAN-Zugriff erlauben.',

            // ── check-filesharing.js ───────────────────────────────────────────
            checkSMB1FailTitle:      'SMBv1 ist erlaubt',
            checkSMB1PassTitle:      'SMBv1 ist deaktiviert',
            checkSMB1Desc:           'SMBv1 ist ein veraltetes Protokoll ohne Verschlüsselung oder Integritätsprüfung. Es ist der Angriffsvektor für EternalBlue (WannaCry, NotPetya). Alle modernen Clients unterstützen SMB2 oder SMB3.',
            checkSMB1Remediation:    'Mindest-SMB-Version auf SMB2 oder höher setzen: UGOS Systemsteuerung › Dateidienste › SMB.',

            checkSMBSigningFailTitle: 'SMB-Signierung wird nicht erzwungen',
            checkSMBSigningPassTitle: 'SMB-Signierung wird erzwungen',
            checkSMBSigningDesc:      'SMB-Signierung stellt sicher, dass Netzwerkpakete während der Übertragung nicht manipuliert wurden. Ohne Signierung ist das NAS anfällig für NTLM-Relay- und Man-in-the-Middle-Angriffe. Der Modus "Wenn erforderlich" ist nicht ausreichend — Signierung muss auf "Erforderlich" gesetzt werden.',
            checkSMBSigningRemediation: 'SMB-Signierung auf "Erforderlich" setzen: UGOS Systemsteuerung › Dateidienste › SMB › Signierungsmodus.',

            checkSMBEncryptFailTitle: 'SMB-Verschlüsselung ist deaktiviert',
            checkSMBEncryptPassTitle: 'SMB-Verschlüsselung ist aktiviert',
            checkSMBEncryptDesc:      'Ohne SMB-Verschlüsselung können Dateiinhalte und Anmeldedaten von jedem auf dem Netzwerkpfad abgefangen werden. SMB-Verschlüsselung (SMB3-Feature) schützt Daten zwischen NAS und Clients.',
            checkSMBEncryptRemediation: 'SMB-Verschlüsselung aktivieren: UGOS Systemsteuerung › Dateidienste › SMB › Verschlüsselungsmodus ("Gewünscht" oder "Erforderlich").',

            checkFTPTLSFailTitle:    'Unverschlüsseltes FTP ist aktiviert',
            checkFTPTLSPassTitle:    'Unverschlüsseltes FTP ist deaktiviert',
            checkFTPTLSDesc:         'FTP ohne TLS überträgt Anmeldedaten und Dateiinhalte im Klartext. Jeder auf dem Netzwerkpfad kann Passwörter und Daten mitlesen. FTPS oder SFTP sollte verwendet werden.',
            checkFTPTLSRemediation:  'Unverschlüsseltes FTP deaktivieren, nur FTPS verwenden: UGOS Systemsteuerung › Dateidienste › FTP.',

            checkFTPAnonFailTitle:   'FTP-Anonymzugriff ist aktiviert',
            checkFTPAnonDesc:        'Anonymer FTP-Zugriff erlaubt Verbindungen ohne Anmeldedaten und macht freigegebene Dateien ohne Authentifizierung zugänglich.',
            checkFTPAnonRemediation: 'Anonymen FTP-Zugriff deaktivieren: UGOS Systemsteuerung › Dateidienste › FTP.',

            checkWebDAVHttpFailTitle: 'WebDAV ist über HTTP erreichbar',
            checkWebDAVHttpPassTitle: 'WebDAV ist nur über HTTPS erreichbar',
            checkWebDAVHttpDesc:      'WebDAV über unverschlüsseltes HTTP überträgt Anmeldedaten und Dateiinhalte im Klartext. Jeder Netzwerkbeobachter kann Authentifizierungstoken und Daten mitlesen.',
            checkWebDAVHttpRemediation: 'HTTP-WebDAV deaktivieren, nur HTTPS verwenden: UGOS Systemsteuerung › Dateidienste › WebDAV.',

            checkNFSV3FailTitle:     'NFS läuft nur mit NFSv3',
            checkNFSV4PassTitle:     'NFS ist für NFSv4 konfiguriert',
            checkNFSV3Desc:          'NFSv3 bietet keine Authentifizierungsmechanismen jenseits IP-basierter Zugriffskontrollen. Jeder Host, der das NAS im Netzwerk erreichen kann, kann potenziell auf NFS-Exporte zugreifen. NFSv4 unterstützt Kerberos-Authentifizierung und bietet deutlich stärkere Zugriffskontrollen.',
            checkNFSV3Remediation:   'NFSv4-Unterstützung aktivieren: UGOS Systemsteuerung › Dateidienste › NFS › Maximales NFS-Protokoll.',

            // ── check-network.js ───────────────────────────────────────────────
            checkDoSFailTitle:       'DoS-Schutz ist deaktiviert',
            checkDoSPassTitle:       'DoS-Schutz ist aktiv',
            checkDoSDesc:            'DoS-Schutz (Denial of Service) verwirft fehlerhafte und Flood-Pakete, bevor sie Systemressourcen erschöpfen können. Ohne diesen Schutz können selbst einfache Netzwerkfluten die NAS-Reaktionsfähigkeit beeinträchtigen.',
            checkDoSRemediation:     'DoS-Schutz aktivieren: UGOS Systemsteuerung › Sicherheit › Firewall › DoS-Schutz.',

            // ── check-users.js ─────────────────────────────────────────────────
            checkPwdLengthFailTitle: 'Minimale Kennwortlänge liegt unter dem empfohlenen Schwellenwert',
            checkPwdLengthPassTitle: 'Minimale Kennwortlänge entspricht dem empfohlenen Schwellenwert',
            checkPwdLengthDesc:      'Die aktuelle Mindestkennwortlänge ({0} Zeichen) liegt unter dem empfohlenen Minimum von 12. Kurze Kennwörter sind deutlich einfacher durch Brute-Force- oder Wörterbuchangriffe zu knacken.',
            checkPwdLengthRemediation: 'Mindestkennwortlänge auf mindestens 12 Zeichen erhöhen: UGOS Systemsteuerung › Benutzer › Kennwortrichtlinie.',

            checkPwdCommonFailTitle: 'Prüfung auf gängige Kennwörter ist nicht aktiviert',
            checkPwdCommonPassTitle: 'Prüfung auf gängige Kennwörter ist aktiv',
            checkPwdCommonDesc:      'Ohne Prüfung auf gängige Kennwörter können Benutzer leicht erratbare Kennwörter wie "Passwort1!" setzen, die technisch die Komplexitätsregeln erfüllen, aber in der Praxis kaum Sicherheit bieten.',
            checkPwdCommonRemediation: 'Prüfung auf gängige Kennwörter aktivieren: UGOS Systemsteuerung › Benutzer › Kennwortrichtlinie.',

            checkPwdSpecialFailTitle: 'Kennwortrichtlinie erfordert keine Sonderzeichen',
            checkPwdSpecialPassTitle: 'Kennwortrichtlinie erfordert Sonderzeichen',
            checkPwdSpecialDesc:      'Die Anforderung mindestens eines Sonderzeichens erhöht die Kennwort-Entropie und die Resistenz gegen Wörterbuchangriffe erheblich.',
            checkPwdSpecialRemediation: 'Sonderzeichen-Anforderung aktivieren: UGOS Systemsteuerung › Benutzer › Kennwortrichtlinie.',

            checkPwdExpiryFailTitle: 'Kennwortablauf wird nicht erzwungen',
            checkPwdExpiryPassTitle: 'Kennwortablauf wird erzwungen',
            checkPwdExpiryDesc:      'Ohne Kennwortablauf bleiben kompromittierte Zugangsdaten unbegrenzt gültig. Ein maximales Kennwortalter begrenzt das Risikofenster bei Datenlecks.',
            checkPwdExpiryRemediation: 'Kennwortablauf aktivieren: UGOS Systemsteuerung › Benutzer › Kennwortablauf.',

            // ── check-maintenance.js ───────────────────────────────────────────
            checkAutoUpdateFailTitle: 'Automatische Firmware-Updates sind deaktiviert',
            checkAutoUpdatePassTitle: 'Automatische Firmware-Updates sind aktiviert',
            checkAutoUpdateDesc:      'Bei deaktivierten automatischen Updates müssen Sicherheits-Patches manuell eingespielt werden. Verzögertes Patching lässt das NAS länger als nötig bekannten Sicherheitslücken ausgesetzt.',
            checkAutoUpdateRemediation: 'Automatische Firmware-Updates aktivieren: UGOS Systemsteuerung › Systemaktualisierung › Automatische Updates.',

            // ── check-bestpractices.js ─────────────────────────────────────────
            bpCheckWideLinksFailTitle: 'SMB Wide Links sind aktiviert',
            bpCheckWideLinksPassTitle: 'SMB Wide Links sind deaktiviert',
            bpCheckWideLinksDesc:      'Wide Links erlauben symbolischen Links innerhalb einer Freigabe, auf Pfade außerhalb der Freigabe zu zeigen. Dies kann SMB-Benutzern unbeabsichtigt Zugriff auf Daten außerhalb ihres vorgesehenen Bereichs geben.',
            bpCheckWideLinksRemediation: 'Wide Links deaktivieren: UGOS Systemsteuerung › Dateidienste › SMB › Erweitert.',

            bpCheckFTPActiveFailTitle: 'FTP-Dienst läuft',
            bpCheckFTPActivePassTitle: 'FTP-Dienst ist deaktiviert',
            bpCheckFTPActiveDesc:      'Der FTP-Dienst ist aktiv. Auch wenn nur FTPS aktiviert ist, erhöht jeder laufende Dienst die Angriffsfläche. Erwägen Sie, FTP vollständig zu deaktivieren und stattdessen SFTP (über SSH) zu verwenden.',
            bpCheckFTPActiveRemediation: 'FTP-Dienst vollständig deaktivieren, wenn nicht benötigt: UGOS Systemsteuerung › Dateidienste › FTP.',

            bpCheckRsyncActiveFailTitle: 'Rsync-Daemon läuft',
            bpCheckRsyncActivePassTitle: 'Rsync-Daemon ist deaktiviert',
            bpCheckRsyncActiveDesc:      'Der Rsync-Daemon stellt einen Netzwerk-Datei-Sync-Dienst bereit. Falls er nicht aktiv für Backups oder Replikation verwendet wird, sollte er deaktiviert werden, um die Angriffsfläche zu reduzieren.',
            bpCheckRsyncActiveRemediation: 'Rsync deaktivieren, wenn nicht benötigt: UGOS Systemsteuerung › Dateidienste › Rsync.',

            bpCheckNFSActiveFailTitle: 'NFS-Dienst läuft',
            bpCheckNFSActivePassTitle: 'NFS-Dienst ist deaktiviert',
            bpCheckNFSActiveDesc:      'NFS ist ein Legacy-Netzwerkdateiprotokoll, das ursprünglich für vertrauenswürdige interne Netzwerke entwickelt wurde. Es bietet keine benutzerbasierte Authentifizierung und verlässt sich ausschließlich auf IP-basierte Zugriffskontrollen. Deaktivieren Sie NFS, wenn Clients stattdessen SMB verwenden können.',
            bpCheckNFSActiveRemediation: 'NFS deaktivieren, wenn nicht benötigt: UGOS Systemsteuerung › Dateidienste › NFS.',

            // ── Compliance view UI ─────────────────────────────────────────────
            frameworksLabel:         'Frameworks',
            clearFiltersBtn:         'Zurücksetzen',
            clearAllFiltersBtn:      'Alle Filter zurücksetzen',
            findingPlural:           'Befunde',
            findingSingular:         'Befund',
            filteredBy:              'gefiltert nach',
            ofTotal:                 'von',
            noFindingsTitle:         'Keine Befunde',
            noFindingsSub:           'Alle Sicherheitsprüfungen bestanden.',
            issueCount:              '1 Befund',
            issuesCount:             '{0} Befunde',
            severityPass:            'OK',
            passedChecks:            'Bestandene Prüfungen',

            // ── Excluded checks section ────────────────────────────────────────
            excludedChecksTitle: 'Bewusst ausgeschlossene Prüfungen',
            excludedChecksDesc:  'UGREEN Inspector verzichtet bewusst auf Empfehlungen, Dienste auf nicht-standardmäßige Portnummern zu verlegen — z. B. SSH von Port 22 wegzuverlegen oder Verwaltungsschnittstellen auf andere Ports umzustellen. Dies ist Security by Obscurity: Es reduziert die Angriffsfläche nicht, erhöht den Betriebsaufwand und vermittelt ein falsches Sicherheitsgefühl. Jeder Portscanner findet einen Dienst unabhängig davon, auf welchem Port er läuft.',

            // ── About ──────────────────────────────────────────────────────────
            aboutBtn:         'Über dieses Tool',
            aboutMaker:       'JKLP CONSULTING · SICHERHEITSAUDIT',
            aboutDesc:        'UGREEN Inspector analysiert UGREEN UGOS-Konfigurationssicherungen (.ugb) direkt im Browser – ohne Datenübertragung. Er prüft die NAS-Konfiguration gegen Sicherheits-Best-Practices und gängige Compliance-Frameworks.',
            aboutSoBNote:     'Inspector schließt „Security by Obscurity"-Prüfungen bewusst aus — z. B. Empfehlungen, Standard-Portnummern zu ändern. Diese erhöhen den Betriebsaufwand, ohne echten Sicherheitsgewinn zu bringen.',
            aboutChannelName: 'JKLP Consulting',
            aboutChannelDesc: 'Security-Audits, NAS-Hardening-Guides und IT-Sicherheit für KMU.',
            aboutWebsiteName: 'jklp.io',
            aboutWebsiteDesc: 'Beratungsgespräch buchen',
            aboutBadgeFree:   'Kostenlos für Privatnutzung',
            aboutBadgeOS:     'Quellcode einsehbar',
            aboutBadgePrivacy:'Keine Daten verlassen Ihren Browser',

            // ── Disclaimer ─────────────────────────────────────────────────────
            disclaimerTitle:  'Wichtiger Hinweis',
            disclaimerItem1:  'Dieses Tool bietet eine automatisierte Analyse als technische Orientierungshilfe und ersetzt kein professionelles Security Audit.',
            disclaimerItem2:  'Es erhebt keinen Anspruch auf Vollständigkeit oder Korrektheit.',
            disclaimerItem3:  'Ergebnisse liefern technische Anhaltspunkte, ersetzen jedoch keine professionelle Sicherheitsberatung.',
            disclaimerItem4:  'Die Zuordnung zu Compliance-Frameworks dient ausschließlich der technischen Orientierung und stellt keine Zertifizierung oder rechtliche Bewertung dar.',
            disclaimerItem5:  'Das Tool analysiert Backups ausschließlich lesend und nimmt keine Änderungen an Ihrem UGREEN NAS vor.',
            disclaimerFooter: 'Benutzung auf eigene Gefahr.',
        },
    };

    // ── Runtime ────────────────────────────────────────────────────────────────

    let _lang = localStorage.getItem('ugr-inspector-lang') || 'en';

    window.t = function (key, ...args) {
        let str = (STRINGS[_lang] && STRINGS[_lang][key]) ||
                  (STRINGS['en']  && STRINGS['en'][key])  ||
                  key;
        args.forEach((arg, i) => { str = str.replace(`{${i}}`, arg); });
        return str;
    };

    window.setLanguage = function (lang) {
        if (!STRINGS[lang]) return;
        _lang = lang;
        localStorage.setItem('ugr-inspector-lang', lang);
        document.documentElement.lang = lang;
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.classList.toggle('lang-btn--active', btn.dataset.lang === lang);
        });
        if (typeof renderApp === 'function') renderApp();
    };

    window.getCurrentLanguage = function () { return _lang; };
}());
