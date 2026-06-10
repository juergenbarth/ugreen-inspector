/**
 * check-filesharing.js — SMB, FTP, WebDAV, NFS security checks for UGREEN UGOS
 *
 * UGREEN Samba config encoding (server_sign_mode):
 *   0 = disabled, 1 = if_required (not enforced), 2 = required
 * UGREEN Samba config encoding (encrypt_mode):
 *   0 = disabled, 1 = desired, 2 = required
 * UGREEN Samba config encoding (smb_protocols):
 *   Array of allowed protocol versions — min(smb_protocols) < 2 means SMBv1 allowed
 */

function checkFileSharing(parseResult) {
    const findings = [];
    const { sambaConfig, ftpConfig, webdavConfig, nfsConfig } = parseResult;

    // ── SMB protocol version ──────────────────────────────────────────────────
    if (sambaConfig) {
        const allowedProtocols = sambaConfig.smb_protocols ?? [];
        const minimumProtocol  = allowedProtocols.length > 0 ? Math.min(...allowedProtocols) : 0;
        const smb1Allowed      = minimumProtocol < 2;
        findings.push({
            id:           'ugr-smb1-allowed',
            severity:     'high',
            status:       smb1Allowed ? 'fail' : 'pass',
            category:     t('catProtocols'),
            frameworks:   [fwRef('CIS','9.4'), fwRef('NIST','CM-7'), fwRef('ISO','A.8.20')],
            affectedItems: ['SMB'],
            title:        smb1Allowed ? t('checkSMB1FailTitle') : t('checkSMB1PassTitle'),
            description:  t('checkSMB1Desc'),
            remediation:  t('checkSMB1Remediation'),
        });

        // ── SMB signing ───────────────────────────────────────────────────────
        const signingMode      = sambaConfig.server_sign_mode ?? 0;
        const signingRequired  = signingMode === 2;
        findings.push({
            id:           'ugr-smb-signing',
            severity:     signingMode === 0 ? 'high' : 'medium',
            status:       signingRequired ? 'pass' : 'fail',
            category:     t('catProtocols'),
            frameworks:   [fwRef('CIS','3.10'), fwRef('NIST','SC-8'), fwRef('ISO','A.8.24'), fwRef('NIS2','Art.21(h)')],
            affectedItems: ['SMB'],
            title:        signingRequired ? t('checkSMBSigningPassTitle') : t('checkSMBSigningFailTitle'),
            description:  t('checkSMBSigningDesc'),
            remediation:  t('checkSMBSigningRemediation'),
        });

        // ── SMB encryption ────────────────────────────────────────────────────
        const encryptionMode    = sambaConfig.encrypt_mode ?? 0;
        const encryptionEnabled = encryptionMode >= 1;
        findings.push({
            id:           'ugr-smb-encryption',
            severity:     'medium',
            status:       encryptionEnabled ? 'pass' : 'fail',
            category:     t('catProtocols'),
            frameworks:   [fwRef('CIS','3.10'), fwRef('NIST','SC-8'), fwRef('ISO','A.8.24'), fwRef('NIS2','Art.21(h)')],
            affectedItems: ['SMB'],
            title:        encryptionEnabled ? t('checkSMBEncryptPassTitle') : t('checkSMBEncryptFailTitle'),
            description:  t('checkSMBEncryptDesc'),
            remediation:  t('checkSMBEncryptRemediation'),
        });
    }

    // ── FTP plain text ────────────────────────────────────────────────────────
    if (ftpConfig) {
        const ftpServiceActive  = ftpConfig.status === true || ftpConfig.status === 1;
        const plainFtpEnabled   = ftpServiceActive && (ftpConfig.enable_ftp === true || ftpConfig.enable_ftp === 1);
        const ftpAnonEnabled    = ftpConfig.anonymous === true || ftpConfig.anonymous === 1;

        if (ftpServiceActive) {
            findings.push({
                id:           'ugr-ftp-plain',
                severity:     'high',
                status:       plainFtpEnabled ? 'fail' : 'pass',
                category:     t('catProtocols'),
                frameworks:   [fwRef('CIS','3.10'), fwRef('NIST','SC-8'), fwRef('ISO','A.8.24')],
                affectedItems: ['FTP'],
                title:        plainFtpEnabled ? t('checkFTPTLSFailTitle') : t('checkFTPTLSPassTitle'),
                description:  t('checkFTPTLSDesc'),
                remediation:  t('checkFTPTLSRemediation'),
            });

            if (ftpAnonEnabled) {
                findings.push({
                    id:           'ugr-ftp-anonymous',
                    severity:     'critical',
                    status:       'fail',
                    category:     t('catProtocols'),
                    frameworks:   [fwRef('CIS','4.8'), fwRef('NIST','CM-7'), fwRef('ISO','A.8.3')],
                    affectedItems: ['FTP'],
                    title:        t('checkFTPAnonFailTitle'),
                    description:  t('checkFTPAnonDesc'),
                    remediation:  t('checkFTPAnonRemediation'),
                });
            }
        }
    }

    // ── WebDAV over HTTP ──────────────────────────────────────────────────────
    if (webdavConfig) {
        const webdavHttpEnabled = webdavConfig.enable_http === true || webdavConfig.enable_http === 1;
        findings.push({
            id:           'ugr-webdav-http',
            severity:     'high',
            status:       webdavHttpEnabled ? 'fail' : 'pass',
            category:     t('catProtocols'),
            frameworks:   [fwRef('CIS','3.10'), fwRef('NIST','SC-8'), fwRef('ISO','A.8.24')],
            affectedItems: ['WebDAV'],
            title:        webdavHttpEnabled ? t('checkWebDAVHttpFailTitle') : t('checkWebDAVHttpPassTitle'),
            description:  t('checkWebDAVHttpDesc'),
            remediation:  t('checkWebDAVHttpRemediation'),
        });
    }

    // ── NFS version ───────────────────────────────────────────────────────────
    if (nfsConfig) {
        const nfsRunning = nfsConfig.enableNfsServer === true || nfsConfig.enableNfsServer === 1;
        if (nfsRunning) {
            const maximumNfsProtocol = nfsConfig.maximumNFSProtocol ?? 'NFSv3';
            const nfsV4Enabled       = maximumNfsProtocol === 'NFSv4';
            findings.push({
                id:           'ugr-nfs-v3-only',
                severity:     'medium',
                status:       nfsV4Enabled ? 'pass' : 'fail',
                category:     t('catProtocols'),
                frameworks:   [fwRef('CIS','9.2'), fwRef('NIST','CM-7'), fwRef('ISO','A.8.20')],
                affectedItems: [`NFS (${maximumNfsProtocol})`],
                title:        nfsV4Enabled ? t('checkNFSV4PassTitle') : t('checkNFSV3FailTitle'),
                description:  t('checkNFSV3Desc'),
                remediation:  t('checkNFSV3Remediation'),
            });
        }
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkFileSharing);
