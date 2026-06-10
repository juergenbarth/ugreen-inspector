/**
 * check-network.js — DoS protection check for UGREEN UGOS
 *
 * firewallConfig comes from securitymgr.firewall → firewall.d/globe.ini
 *   dos = 0 → DoS protection disabled
 *   dos = 1 → DoS protection enabled
 */

function checkNetwork(parseResult) {
    const findings = [];
    const { firewallConfig } = parseResult;

    if (!firewallConfig) return findings;

    findings.push({
        id:           'ugr-dos-protection',
        severity:     'medium',
        status:       firewallConfig.dosEnabled ? 'pass' : 'fail',
        category:     t('catNetwork'),
        frameworks:   [fwRef('CIS','12.2'), fwRef('NIST','SC-7'), fwRef('ISO','A.8.20')],
        affectedItems: [t('affectedAllInterfaces')],
        title:        firewallConfig.dosEnabled ? t('checkDoSPassTitle') : t('checkDoSFailTitle'),
        description:  t('checkDoSDesc'),
        remediation:  t('checkDoSRemediation'),
    });

    return findings;
}

COMPLIANCE_CHECKS.push(checkNetwork);
