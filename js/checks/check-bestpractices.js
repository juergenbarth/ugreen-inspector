/**
 * check-bestpractices.js — Best practice checks for UGREEN UGOS
 *
 * These findings do not affect the security score.
 */

function checkBestPractices(parseResult) {
    const findings = [];
    const { sambaConfig, ftpConfig, rsyncConfig, nfsConfig } = parseResult;

    // ── SMB wide links (symlinks crossing share boundaries) ───────────────────
    if (sambaConfig) {
        const wideLinksEnabled = sambaConfig.enable_wide_links === true || sambaConfig.enable_wide_links === 1;
        findings.push({
            id:           'ugr-bp-smb-wide-links',
            severity:     'low',
            status:       wideLinksEnabled ? 'fail' : 'pass',
            category:     t('catBPSMB'),
            frameworks:   [],
            affectedItems: ['SMB'],
            title:        wideLinksEnabled ? t('bpCheckWideLinksFailTitle') : t('bpCheckWideLinksPassTitle'),
            description:  t('bpCheckWideLinksDesc'),
            remediation:  t('bpCheckWideLinksRemediation'),
        });
    }

    // ── FTP service active (even if only FTPS) ────────────────────────────────
    if (ftpConfig) {
        const ftpServiceActive = ftpConfig.status === true || ftpConfig.status === 1;
        findings.push({
            id:           'ugr-bp-ftp-active',
            severity:     'low',
            status:       ftpServiceActive ? 'fail' : 'pass',
            category:     t('catBPFileServices'),
            frameworks:   [],
            affectedItems: ['FTP'],
            title:        ftpServiceActive ? t('bpCheckFTPActiveFailTitle') : t('bpCheckFTPActivePassTitle'),
            description:  t('bpCheckFTPActiveDesc'),
            remediation:  t('bpCheckFTPActiveRemediation'),
        });
    }

    // ── Rsync daemon active ────────────────────────────────────────────────────
    if (rsyncConfig) {
        const rsyncActive = rsyncConfig.status === true || rsyncConfig.status === 1;
        findings.push({
            id:           'ugr-bp-rsync-active',
            severity:     'low',
            status:       rsyncActive ? 'fail' : 'pass',
            category:     t('catBPFileServices'),
            frameworks:   [],
            affectedItems: ['Rsync'],
            title:        rsyncActive ? t('bpCheckRsyncActiveFailTitle') : t('bpCheckRsyncActivePassTitle'),
            description:  t('bpCheckRsyncActiveDesc'),
            remediation:  t('bpCheckRsyncActiveRemediation'),
        });
    }

    // ── NFS service active ─────────────────────────────────────────────────────
    if (nfsConfig) {
        const nfsActive = nfsConfig.enableNfsServer === true || nfsConfig.enableNfsServer === 1;
        findings.push({
            id:           'ugr-bp-nfs-active',
            severity:     'low',
            status:       nfsActive ? 'fail' : 'pass',
            category:     t('catBPFileServices'),
            frameworks:   [],
            affectedItems: ['NFS'],
            title:        nfsActive ? t('bpCheckNFSActiveFailTitle') : t('bpCheckNFSActivePassTitle'),
            description:  t('bpCheckNFSActiveDesc'),
            remediation:  t('bpCheckNFSActiveRemediation'),
        });
    }

    return findings;
}

BEST_PRACTICES_CHECKS.push(checkBestPractices);
