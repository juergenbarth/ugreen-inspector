/**
 * compliance-engine.js
 *
 * Core infrastructure for the UGREEN Inspector compliance checks.
 *
 * Adding a new check:
 *   Create a file in js/checks/, implement your function, then at the bottom:
 *     COMPLIANCE_CHECKS.push(myCheckFunction);
 *
 * Check function signature:
 *   function myCheck(parseResult) → Finding[]
 *
 *   parseResult — structured object from ugb-pipeline.js
 *
 * Finding shape:
 * {
 *   id            {string}   unique, stable identifier
 *   title         {string}   short human-readable title
 *   description   {string}   longer explanation of the issue
 *   severity      {string}   'critical' | 'high' | 'medium' | 'low' | 'info'
 *   status        {string}   'fail' | 'pass'
 *   category      {string}   display category
 *   frameworks    {Array}    [{code, ref, label}]
 *   affectedItems {string[]} human-readable list of affected objects
 *   remediation   {string}   concrete fix steps
 * }
 */

// ── Check registries ───────────────────────────────────────────────────────────

/** @type {Array<function(Object): Object[]>} */
const COMPLIANCE_CHECKS = [];

/** @type {Array<function(Object): Object[]>} */
const BEST_PRACTICES_CHECKS = [];

// ── Framework reference builder ────────────────────────────────────────────────

/**
 * @param {'CIS'|'NIST'|'ISO'|'NIS2'|'PCI'} code
 * @param {string} ref
 * @returns {{ code: string, ref: string, label: string }}
 */
function fwRef(code, ref) {
    return { code, ref, label: `${code} ${ref}` };
}

// ── Scoring ────────────────────────────────────────────────────────────────────

const SEVERITY_PENALTY = {
    critical: 20,
    high:     10,
    medium:    5,
    low:       2,
    info:      0,
};

function calculateSecurityScore(findings) {
    const totalPenalty = findings
        .filter(f => f.status === 'fail')
        .reduce((sum, f) => sum + (SEVERITY_PENALTY[f.severity] ?? 0), 0);
    return Math.max(0, 100 - totalPenalty);
}

function scoreToGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
}

function scoreToVerdict(score) {
    if (score >= 90) return t('verdictStrong');
    if (score >= 80) return t('verdictGood');
    if (score >= 70) return t('verdictAcceptable');
    if (score >= 60) return t('verdictImprove');
    if (score >= 40) return t('verdictExposure');
    return t('verdictCritical');
}

// ── Orchestrators ──────────────────────────────────────────────────────────────

/**
 * @param {Object} parseResult  structured result from ugb-pipeline.js
 * @returns {Object[]}
 */
function runAllChecks(parseResult) {
    return COMPLIANCE_CHECKS.flatMap(fn => fn(parseResult));
}

/**
 * @param {Object} parseResult  structured result from ugb-pipeline.js
 * @returns {Object[]}
 */
function runAllBestPracticesChecks(parseResult) {
    return BEST_PRACTICES_CHECKS.flatMap(fn => fn(parseResult));
}
