/**
 * check-users.js — Password policy and expiry checks for UGREEN UGOS
 *
 * password-policy.json fields:
 *   min_length            {number}  minimum password length
 *   disable_common_pwd    {boolean} true = common passwords are blocked
 *   must_contain_case     {boolean} true = mixed case required
 *   must_contain_num      {boolean} true = numbers required
 *   must_contain_special_char {boolean} true = special chars required
 *
 * passwd.config fields:
 *   enable   {boolean} true = password expiry is enforced
 *   max_days {number}  maximum password age in days
 */

const RECOMMENDED_MIN_PASSWORD_LENGTH = 12;

function checkUsers(parseResult) {
    const findings = [];
    const { userConfig } = parseResult;

    if (!userConfig) return findings;

    const { passwordPolicy, passwordExpiry } = userConfig;

    // ── Password minimum length ───────────────────────────────────────────────
    if (passwordPolicy) {
        const minLength            = passwordPolicy.min_length ?? 0;
        const meetsLengthThreshold = minLength >= RECOMMENDED_MIN_PASSWORD_LENGTH;
        findings.push({
            id:           'ugr-pwd-length',
            severity:     'medium',
            status:       meetsLengthThreshold ? 'pass' : 'fail',
            category:     t('catUsers'),
            frameworks:   [fwRef('CIS','4.10'), fwRef('NIST','IA-5'), fwRef('ISO','A.8.5')],
            affectedItems: [t('affectedAllUsers')],
            title:        meetsLengthThreshold ? t('checkPwdLengthPassTitle') : t('checkPwdLengthFailTitle'),
            description:  t('checkPwdLengthDesc', minLength),
            remediation:  t('checkPwdLengthRemediation'),
        });

        // ── Common password check ─────────────────────────────────────────────
        const commonPwdBlocked = passwordPolicy.disable_common_pwd === true;
        findings.push({
            id:           'ugr-pwd-common',
            severity:     'low',
            status:       commonPwdBlocked ? 'pass' : 'fail',
            category:     t('catUsers'),
            frameworks:   [fwRef('CIS','4.10'), fwRef('NIST','IA-5'), fwRef('ISO','A.8.5')],
            affectedItems: [t('affectedAllUsers')],
            title:        commonPwdBlocked ? t('checkPwdCommonPassTitle') : t('checkPwdCommonFailTitle'),
            description:  t('checkPwdCommonDesc'),
            remediation:  t('checkPwdCommonRemediation'),
        });

        // ── Special characters required ────────────────────────────────────────
        const specialCharsRequired = passwordPolicy.must_contain_special_char === true;
        findings.push({
            id:           'ugr-pwd-special',
            severity:     'low',
            status:       specialCharsRequired ? 'pass' : 'fail',
            category:     t('catUsers'),
            frameworks:   [fwRef('CIS','4.10'), fwRef('NIST','IA-5'), fwRef('ISO','A.8.5')],
            affectedItems: [t('affectedAllUsers')],
            title:        specialCharsRequired ? t('checkPwdSpecialPassTitle') : t('checkPwdSpecialFailTitle'),
            description:  t('checkPwdSpecialDesc'),
            remediation:  t('checkPwdSpecialRemediation'),
        });
    }

    // ── Password expiry ───────────────────────────────────────────────────────
    if (passwordExpiry) {
        const expiryEnabled = passwordExpiry.enable === true;
        findings.push({
            id:           'ugr-pwd-expiry',
            severity:     'low',
            status:       expiryEnabled ? 'pass' : 'fail',
            category:     t('catUsers'),
            frameworks:   [fwRef('NIST','IA-5'), fwRef('ISO','A.8.5'), fwRef('NIS2','Art.21(b)')],
            affectedItems: [t('affectedAllUsers')],
            title:        expiryEnabled ? t('checkPwdExpiryPassTitle') : t('checkPwdExpiryFailTitle'),
            description:  t('checkPwdExpiryDesc'),
            remediation:  t('checkPwdExpiryRemediation'),
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkUsers);
