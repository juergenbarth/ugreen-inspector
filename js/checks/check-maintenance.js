/**
 * check-maintenance.js — Firmware update best-practice check for UGREEN UGOS
 *
 * updateConfig (system.json):
 *   auto_update: 0 → automatic installation disabled (notify/manual — preferred)
 *   auto_update: 1 → automatic installation enabled
 *
 * Rationale: CIS 7.3 requires timely patching via an organised process, not
 * necessarily auto-install. Auto-install on a NAS risks unexpected reboots and
 * applies untested firmware without a review window. Notify-only satisfies CIS 7.3
 * when the admin acts on notifications promptly.
 */

function checkMaintenanceBP(parseResult) {
    const findings = [];
    const { updateConfig } = parseResult;

    if (!updateConfig) return findings;

    const autoInstallEnabled = updateConfig.auto_update === 1;
    findings.push({
        id:            'ugr-bp-auto-update',
        severity:      'low',
        status:        autoInstallEnabled ? 'fail' : 'pass',
        category:      t('catMaintenance'),
        frameworks:    [fwRef('CIS','7.3'), fwRef('NIST','SI-2'), fwRef('ISO','A.8.8')],
        affectedItems: ['UGOS Firmware'],
        title:         autoInstallEnabled ? t('bpCheckAutoUpdateFailTitle') : t('bpCheckAutoUpdatePassTitle'),
        description:   t('bpCheckAutoUpdateDesc'),
        remediation:   t('bpCheckAutoUpdateRemediation'),
    });

    return findings;
}

BEST_PRACTICES_CHECKS.push(checkMaintenanceBP);
