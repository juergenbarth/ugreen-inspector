/**
 * check-maintenance.js — Firmware update check for UGREEN UGOS
 *
 * updateConfig (system.json):
 *   auto_update: 0 → automatic updates disabled
 *   auto_update: 1 → automatic updates enabled
 */

function checkMaintenance(parseResult) {
    const findings = [];
    const { updateConfig } = parseResult;

    if (!updateConfig) return findings;

    const autoUpdateEnabled = updateConfig.auto_update === 1;
    findings.push({
        id:           'ugr-auto-update',
        severity:     'medium',
        status:       autoUpdateEnabled ? 'pass' : 'fail',
        category:     t('catMaintenance'),
        frameworks:   [fwRef('CIS','7.3'), fwRef('NIST','SI-2'), fwRef('ISO','A.8.8'), fwRef('NIS2','Art.21(b)')],
        affectedItems: ['UGOS Firmware'],
        title:        autoUpdateEnabled ? t('checkAutoUpdatePassTitle') : t('checkAutoUpdateFailTitle'),
        description:  t('checkAutoUpdateDesc'),
        remediation:  t('checkAutoUpdateRemediation'),
    });

    return findings;
}

COMPLIANCE_CHECKS.push(checkMaintenance);
