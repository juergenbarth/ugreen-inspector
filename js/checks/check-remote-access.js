/**
 * check-remote-access.js — SSH and Telnet checks for UGREEN UGOS
 *
 * terminal_custom INI encoding:
 *   enable = 1  → service is enabled
 *   enable = 2  → service is disabled
 *   permit_lan_access_only = 1 → LAN only
 *   permit_lan_access_only = 2 → WAN + LAN
 */

function checkRemoteAccess(parseResult) {
    const findings = [];
    const { terminalConfig } = parseResult;

    if (!terminalConfig) return findings;

    // ── Telnet ────────────────────────────────────────────────────────────────
    const telnetEnabled = terminalConfig.telnet.enable === 1;
    findings.push({
        id:           'ugr-telnet-enabled',
        severity:     'critical',
        status:       telnetEnabled ? 'fail' : 'pass',
        category:     t('catRemoteAccess'),
        frameworks:   [fwRef('CIS','4.6'), fwRef('NIST','CM-7'), fwRef('ISO','A.8.20'), fwRef('NIS2','Art.21(h)')],
        affectedItems: ['Telnet'],
        title:        telnetEnabled ? t('checkTelnetFailTitle') : t('checkTelnetPassTitle'),
        description:  t('checkTelnetDesc'),
        remediation:  t('checkTelnetRemediation'),
    });

    // ── SSH ───────────────────────────────────────────────────────────────────
    const sshEnabled = terminalConfig.ssh.enable === 1;
    findings.push({
        id:           'ugr-ssh-enabled',
        severity:     'medium',
        status:       sshEnabled ? 'fail' : 'pass',
        category:     t('catRemoteAccess'),
        frameworks:   [fwRef('CIS','4.6'), fwRef('NIST','CM-7'), fwRef('ISO','A.8.20')],
        affectedItems: ['SSH'],
        title:        sshEnabled ? t('checkSSHFailTitle') : t('checkSSHPassTitle'),
        description:  t('checkSSHDesc'),
        remediation:  t('checkSSHRemediation'),
    });

    // ── SSH accessible from WAN ───────────────────────────────────────────────
    if (sshEnabled) {
        const sshLanOnly = terminalConfig.ssh.permitLanAccessOnly === 1;
        findings.push({
            id:           'ugr-ssh-wan-access',
            severity:     'high',
            status:       sshLanOnly ? 'pass' : 'fail',
            category:     t('catRemoteAccess'),
            frameworks:   [fwRef('CIS','12.2'), fwRef('NIST','SC-7'), fwRef('ISO','A.8.20')],
            affectedItems: ['SSH'],
            title:        sshLanOnly ? t('checkSSHLanOnlyPassTitle') : t('checkSSHLanOnlyFailTitle'),
            description:  t('checkSSHLanOnlyDesc'),
            remediation:  t('checkSSHLanOnlyRemediation'),
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkRemoteAccess);
