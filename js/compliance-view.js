/**
 * compliance-view.js
 *
 * Renders the compliance report dashboard.
 * Adapted from Synology Inspector for UGREEN UGOS.
 *
 * Depends on: compliance-engine.js, i18n.js, app.js (escapeHtml)
 */

// ── Framework display metadata ────────────────────────────────────────────────

const FRAMEWORK_META = {
    CIS:  { label: 'CIS Controls v8',  color: '#f97316' },
    NIST: { label: 'NIST SP 800-53',   color: '#60a5fa' },
    ISO:  { label: 'ISO 27001:2022',   color: '#a78bfa' },
    NIS2: { label: 'NIS2 Directive',   color: '#34d399' },
};

const FW_REF_DESCRIPTIONS = {
    'CIS 3.10':    { title: 'Encrypt Sensitive Data in Transit',              body: 'Encrypt sensitive data in transit using a secure protocol such as Transport Layer Security (TLS). Do not use older versions of TLS.' },
    'CIS 4.6':     { title: 'Securely Manage Enterprise Assets and Software', body: 'Securely manage enterprise assets and software. Use encrypted protocols such as SSH rather than Telnet for remote management. Disable unnecessary services.' },
    'CIS 4.8':     { title: 'Uninstall or Disable Unnecessary Services',      body: 'Uninstall or disable unnecessary services on enterprise assets and software, such as unused file sharing services, web application modules, or remote management services not required for business purposes.' },
    'CIS 4.10':    { title: 'Configure Automatic Session Locking on Enterprise Assets', body: 'Configure automatic session locking on enterprise assets after a defined period of inactivity. Ensure account lockout policies are configured to block access after failed authentication attempts.' },
    'CIS 7.3':     { title: 'Perform Automated Operating System Patch Management', body: 'Perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, cadence.' },
    'CIS 9.2':     { title: 'Ensure Only Approved Ports and Services Are Listening', body: 'Ensure that only network ports, protocols, and services with validated business needs are listening on each enterprise asset.' },
    'CIS 9.4':     { title: 'Block Unnecessary File Sharing Services',         body: 'Block unnecessary file sharing services and protocols including SMBv1. Restrict access to file shares to authorised users only, using encrypted protocols.' },
    'CIS 12.2':    { title: 'Establish and Maintain a Secure Network Architecture', body: 'Establish and maintain a secure network architecture. Controls must address segmentation, least privilege, and availability. Review at least annually.' },
    'NIST CM-7':   { title: 'Least Functionality',                             body: 'Configure the system to provide only essential capabilities. Prohibit or restrict functions, ports, protocols, and services not required.' },
    'NIST IA-5':   { title: 'Authenticator Management',                        body: 'Manage information system authenticators by establishing minimum password complexity and length. Enforce restrictions on password reuse and implement account management procedures.' },
    'NIST SC-7':   { title: 'Boundary Protection',                             body: 'Monitor and control communications at the external boundary. Connect to external networks only through managed interfaces consisting of boundary protection devices.' },
    'NIST SC-8':   { title: 'Transmission Confidentiality and Integrity',       body: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes during transmission.' },
    'NIST SI-2':   { title: 'Flaw Remediation',                                body: 'Identify, report, and correct information system flaws. Install security-relevant software updates within an organizationally defined time period after release.' },
    'ISO A.8.3':   { title: 'Information Access Restriction',                  body: 'Access to information and application system functions shall be restricted in accordance with the access control policy. Anonymous or unauthenticated access shall be avoided.' },
    'ISO A.8.5':   { title: 'Secure Authentication',                           body: 'Secure authentication technologies and procedures shall be implemented based on information access restrictions and the access control policy, including account lockout for failed attempts.' },
    'ISO A.8.8':   { title: 'Management of Technical Vulnerabilities',          body: 'Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion and the organization shall evaluate its exposure to such vulnerabilities. Appropriate measures shall be taken to address the associated risk.' },
    'ISO A.8.20':  { title: 'Networks Security',                               body: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications. Unnecessary services and access paths shall be disabled.' },
    'ISO A.8.24':  { title: 'Use of Cryptography',                             body: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented to protect confidentiality, authenticity and integrity.' },
    'NIS2 Art.21(b)': { title: 'Incident Handling',                            body: 'Entities must implement policies for handling cybersecurity incidents, including detection, reporting, and response. Limiting external attack surface reduces incident likelihood (NIS2 Art. 21 para. 2 lit. b).' },
    'NIS2 Art.21(h)': { title: 'Cryptography and Encryption',                 body: 'Entities must implement policies regarding the use of cryptography and, where appropriate, encryption to protect information in transit (NIS2 Art. 21 para. 2 lit. h).' },
};

// ── Severity metadata ──────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
    critical: '#aa0808',
    high:     '#e76500',
    medium:   '#b44f00',
    low:      '#0064d9',
    info:     '#758ca4',
};

const SEVERITY_SORT_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── View state ────────────────────────────────────────────────────────────────

const complianceState = {
    severityFilter:  null,
    frameworkFilter: null,
    expandedIds:     new Set(),
};

function setComplianceSeverityFilter(severity) {
    complianceState.severityFilter =
        complianceState.severityFilter === severity ? null : severity;
    rerenderCompliance();
}

function setComplianceFrameworkFilter(code) {
    complianceState.frameworkFilter =
        complianceState.frameworkFilter === code ? null : code;
    rerenderCompliance();
}

function clearAllComplianceFilters() {
    complianceState.severityFilter  = null;
    complianceState.frameworkFilter = null;
    rerenderCompliance();
}

function toggleFindingExpanded(id) {
    if (complianceState.expandedIds.has(id)) {
        complianceState.expandedIds.delete(id);
    } else {
        complianceState.expandedIds.add(id);
    }
    rerenderCompliance();
}

let _cachedFindings = null;

function rerenderCompliance() {
    if (!_cachedFindings) return;
    const el = document.getElementById('compliance-view-root');
    if (!el) return;
    const scrollArea = el.querySelector('.findings-scroll-area');
    const scrollTop  = scrollArea ? scrollArea.scrollTop : 0;
    el.innerHTML     = renderComplianceView(_cachedFindings);
    const newScroll  = el.querySelector('.findings-scroll-area');
    if (newScroll) newScroll.scrollTop = scrollTop;
}

// ── FW reference popover ──────────────────────────────────────────────────────

function showFwRefPopover(label, anchorEl) {
    closeFwRefPopover();
    const info = FW_REF_DESCRIPTIONS[label];
    if (!info) return;

    const pop = document.createElement('div');
    pop.id = 'fw-ref-popover';
    pop.className = 'fw-ref-popover';
    pop.innerHTML = `
        <div class="fw-ref-popover-label">${escapeHtml(label)}</div>
        <div class="fw-ref-popover-title">${escapeHtml(info.title)}</div>
        <div class="fw-ref-popover-body">${escapeHtml(info.body)}</div>
    `;
    document.body.appendChild(pop);

    const rect = anchorEl.getBoundingClientRect();
    const pw   = 320;
    let left = rect.left;
    let top  = rect.bottom + 6;
    if (left + pw > window.innerWidth - 12)  left = window.innerWidth - pw - 12;
    if (top + pop.offsetHeight > window.innerHeight - 12) top = rect.top - pop.offsetHeight - 6;
    pop.style.left = `${Math.max(12, left)}px`;
    pop.style.top  = `${Math.max(8, top)}px`;

    setTimeout(() => document.addEventListener('click', closeFwRefPopover, { once: true }), 0);
}

function closeFwRefPopover() {
    document.getElementById('fw-ref-popover')?.remove();
}

// ── Top-level renderer ────────────────────────────────────────────────────────

function renderComplianceView(findings) {
    _cachedFindings = findings;

    const failFindings = findings.filter(f => f.status === 'fail');
    const passFindings = findings.filter(f => f.status === 'pass');
    const score        = calculateSecurityScore(findings);

    let visible = [...failFindings];
    if (complianceState.frameworkFilter) {
        visible = visible.filter(f =>
            f.frameworks.some(fw => fw.code === complianceState.frameworkFilter));
    }
    if (complianceState.severityFilter) {
        visible = visible.filter(f => f.severity === complianceState.severityFilter);
    }
    visible.sort((a, b) =>
        (SEVERITY_SORT_ORDER[a.severity] ?? 5) - (SEVERITY_SORT_ORDER[b.severity] ?? 5));

    return `
        ${renderScoreHeader(findings, failFindings, score)}
        ${renderStatusBar(failFindings, visible)}
        <div class="findings-scroll-area">
            ${renderFindingsByCategory(visible)}
            ${renderPassedSection(passFindings)}
            ${renderExcludedChecksSection()}
            ${renderDisclaimer()}
        </div>
    `;
}

// ── Score header ──────────────────────────────────────────────────────────────

function renderScoreHeader(allFindings, failFindings, score) {
    const grade      = scoreToGrade(score);
    const verdict    = scoreToVerdict(score);
    const gradeColor = score >= 80 ? '#256f3a' : score >= 60 ? '#e76500' : '#aa0808';

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of failFindings) {
        if (counts[f.severity] !== undefined) counts[f.severity]++;
    }

    const kpiTiles = [
        { key: 'critical', labelKey: 'severityCritical', color: '#aa0808' },
        { key: 'high',     labelKey: 'severityHigh',     color: '#e76500' },
        { key: 'medium',   labelKey: 'severityMedium',   color: '#b44f00' },
        { key: 'low',      labelKey: 'severityLow',      color: '#0064d9' },
    ].map(({ key, labelKey, color }) => {
        const count    = counts[key] || 0;
        const isActive = complianceState.severityFilter === key;
        return `
            <button class="kpi-tile ${isActive ? 'kpi-tile--active' : ''} ${count === 0 ? 'kpi-tile--empty' : ''}"
                    style="--kpi-color: ${color}"
                    ${count > 0 ? `onclick="setComplianceSeverityFilter('${key}')"` : 'disabled'}>
                <span class="kpi-number">${count}</span>
                <span class="kpi-label">${t(labelKey)}</span>
            </button>
        `;
    }).join('');

    const frameworkStats = {};
    for (const f of allFindings) {
        for (const fw of f.frameworks) {
            if (!frameworkStats[fw.code]) frameworkStats[fw.code] = { fail: 0, pass: 0 };
            if (f.status === 'fail') frameworkStats[fw.code].fail++;
            else                     frameworkStats[fw.code].pass++;
        }
    }

    const fwChips = Object.entries(FRAMEWORK_META).map(([code, meta]) => {
        const stats     = frameworkStats[code] || { fail: 0, pass: 0 };
        const isActive  = complianceState.frameworkFilter === code;
        const hasIssues = stats.fail > 0;
        return `
            <button class="fw-chip ${isActive ? 'fw-chip--active' : ''} ${hasIssues ? 'fw-chip--issues' : 'fw-chip--clean'}"
                    style="--chip-color: ${meta.color}"
                    onclick="setComplianceFrameworkFilter('${code}')"
                    title="${meta.label}">
                ${code}
                ${hasIssues
                    ? `<span class="fw-chip-count">${stats.fail}</span>`
                    : '<span class="fw-chip-clean">✓</span>'}
            </button>
        `;
    }).join('');

    const hasFilter = complianceState.severityFilter || complianceState.frameworkFilter;
    const clearBtn  = hasFilter
        ? `<button class="chip-clear-btn" onclick="clearAllComplianceFilters()">${t('clearFiltersBtn')}</button>` : '';

    return `
        <div class="compliance-header">
            <div class="compliance-score-area">
                <div class="score-kpi-block">
                    <div class="score-kpi-number" style="color:${gradeColor}">
                        <span class="score-kpi-val">${score}</span><span class="score-kpi-denom">/100</span>
                    </div>
                    <div class="score-kpi-detail">
                        <div class="score-progress-bar" role="progressbar"
                             aria-valuenow="${score}" aria-valuemin="0" aria-valuemax="100">
                            <div class="score-progress-fill" style="width:${score}%;background:${gradeColor}"></div>
                        </div>
                        <div class="score-grade-row">
                            <span class="score-grade-letter" style="color:${gradeColor}">${grade}</span>
                            <span class="score-verdict">${verdict}</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="compliance-separator"></div>
            <div class="compliance-metrics-area">
                <div class="kpi-row">${kpiTiles}</div>
                <div class="fw-filter-row">
                    <span class="filter-row-label">${t('frameworksLabel')}</span>
                    ${fwChips}
                    ${clearBtn}
                </div>
            </div>
        </div>
    `;
}

// ── Status bar ────────────────────────────────────────────────────────────────

function renderStatusBar(allFail, visible) {
    const af = complianceState.frameworkFilter;
    const as = complianceState.severityFilter;
    const hasFilter = af || as;

    const labels = [];
    if (af) labels.push(FRAMEWORK_META[af]?.label || af);
    if (as) labels.push(as);

    return `
        <div class="compliance-status-bar">
            <span class="status-bar-count">${visible.length}</span>
            <span class="status-bar-label">
                ${visible.length !== 1 ? t('findingPlural') : t('findingSingular')}
                ${hasFilter
                    ? `<span class="status-bar-filter">· ${t('filteredBy')} ${escapeHtml(labels.join(', '))}</span>`
                    : `<span class="status-bar-total">(${t('ofTotal')} ${allFail.length})</span>`}
            </span>
            ${hasFilter
                ? `<button class="status-bar-clear" onclick="clearAllComplianceFilters()">${t('clearAllFiltersBtn')}</button>`
                : ''}
        </div>
    `;
}

// ── Findings grouped by category ──────────────────────────────────────────────

function renderFindingsByCategory(findings) {
    if (findings.length === 0) {
        return `
            <div class="findings-empty-state">
                <div class="findings-empty-icon">✓</div>
                <div class="findings-empty-title">${t('noFindingsTitle')}</div>
                <div class="findings-empty-sub">${t('noFindingsSub')}</div>
            </div>
        `;
    }

    const order   = [];
    const grouped = {};
    for (const f of findings) {
        if (!grouped[f.category]) { grouped[f.category] = []; order.push(f.category); }
        grouped[f.category].push(f);
    }

    return order.map(cat => {
        const catFindings = grouped[cat];
        const n           = catFindings.length;
        const topColor    = SEVERITY_COLOR[catFindings[0].severity] || SEVERITY_COLOR.info;
        const issueText   = n === 1 ? t('issueCount') : t('issuesCount', n);
        return `
            <div class="category-group">
                <div class="category-header" style="--cat-color: ${topColor}">
                    <span class="category-header-name">${escapeHtml(cat)}</span>
                    <span class="category-header-count">${issueText}</span>
                </div>
                <div class="category-findings">
                    ${catFindings.map(renderFindingCard).join('')}
                </div>
            </div>
        `;
    }).join('');
}

// ── Finding card ──────────────────────────────────────────────────────────────

function renderFindingCard(f) {
    const isExpanded  = complianceState.expandedIds.has(f.id);
    const stripeColor = SEVERITY_COLOR[f.severity] || '#64748b';
    const sevLabel    = t('severity' + f.severity.charAt(0).toUpperCase() + f.severity.slice(1));

    const fwTags = f.frameworks.map(fw => {
        const meta    = FRAMEWORK_META[fw.code] || { color: '#6b7d93' };
        const hasInfo = !!FW_REF_DESCRIPTIONS[fw.label];
        return `<button class="fw-tag ${hasInfo ? 'fw-tag--clickable' : ''}"
                        style="color:${meta.color};background:${meta.color}18;border-color:${meta.color}33"
                        ${hasInfo ? `onclick="event.stopPropagation();showFwRefPopover('${fw.label}',this)"` : ''}
                >${fw.label}</button>`;
    }).join('');

    const body = isExpanded ? `
        <div class="finding-body">
            ${f.description ? `<p class="finding-description">${escapeHtml(f.description)}</p>` : ''}
            ${f.affectedItems && f.affectedItems.length > 0 ? `
                <div class="finding-section">
                    <div class="finding-section-title">${t('labelAffected')}</div>
                    <ul class="finding-affected-list">
                        ${f.affectedItems.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            ${f.remediation ? `
                <div class="finding-section finding-section--remediation">
                    <div class="finding-section-title">${t('labelRemediation')}</div>
                    <p class="finding-remediation">${escapeHtml(f.remediation)}</p>
                </div>
            ` : ''}
        </div>
    ` : '';

    return `
        <div class="finding-card" style="--stripe-color: ${stripeColor}">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header" onclick="toggleFindingExpanded('${f.id}')">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--${f.severity}">${sevLabel}</span>
                    </div>
                    <div class="finding-title">${escapeHtml(f.title)}</div>
                    <div class="finding-meta">
                        <div class="finding-fw-tags">${fwTags}</div>
                    </div>
                    <span class="finding-toggle ${isExpanded ? 'finding-toggle--open' : ''}">▶</span>
                </div>
                ${body}
            </div>
        </div>
    `;
}

// ── Passed checks section ─────────────────────────────────────────────────────

function renderPassedSection(passFindings) {
    if (passFindings.length === 0) return '';

    const cards = passFindings.map(f => `
        <div class="finding-card finding-card--pass" style="--stripe-color: #34d399">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header finding-header--pass">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--pass">${t('severityPass')}</span>
                        <span class="finding-category">${escapeHtml(f.category)}</span>
                    </div>
                    <div class="finding-title finding-title--pass">${escapeHtml(f.title)}</div>
                </div>
            </div>
        </div>
    `).join('');

    return `
        <div class="passed-section">
            <div class="passed-section-header">
                ${t('passedChecks')} <span class="passed-count">${passFindings.length}</span>
            </div>
            <div class="passed-list">${cards}</div>
        </div>
    `;
}

// ── Excluded checks ───────────────────────────────────────────────────────────

function renderExcludedChecksSection() {
    const filterIcon = `<svg class="excluded-checks-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M2 3h12l-4.5 5.5V13l-3-1.5V8.5L2 3z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
    </svg>`;
    return `
        <details class="excluded-checks-section">
            <summary class="excluded-checks-summary">
                ${filterIcon}
                <span>${t('excludedChecksTitle')}</span>
                <span class="excluded-checks-toggle">▶</span>
            </summary>
            <p class="excluded-checks-body">${t('excludedChecksDesc')}</p>
        </details>
    `;
}

// ── Disclaimer ────────────────────────────────────────────────────────────────

function renderDisclaimer() {
    const icon = `<svg class="disclaimer-icon" width="18" height="18" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="8" cy="8" r="7.25" stroke="currentColor" stroke-width="1.5"/>
        <rect x="7.25" y="6.5" width="1.5" height="5" rx=".75" fill="currentColor"/>
        <rect x="7.25" y="4" width="1.5" height="1.5" rx=".75" fill="currentColor"/>
    </svg>`;
    return `
        <div class="disclaimer-box compliance-disclaimer">
            <div class="disclaimer-header">
                ${icon}
                <strong class="disclaimer-title">${t('disclaimerTitle')}</strong>
            </div>
            <ul class="disclaimer-list">
                <li>${t('disclaimerItem1')}</li>
                <li>${t('disclaimerItem2')}</li>
                <li>${t('disclaimerItem3')}</li>
                <li>${t('disclaimerItem4')}</li>
                <li>${t('disclaimerItem5')}</li>
            </ul>
            <p class="disclaimer-footer">${t('disclaimerFooter')}</p>
        </div>
    `;
}
