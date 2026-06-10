/**
 * ugb-pipeline.js
 *
 * Parses a UGREEN UGOS configuration backup (.ugb) in the browser.
 *
 * File format:
 *   Line 0: "Version:2.0\n"
 *   Followed by: metadata JSON + N service blocks
 *
 *   Each service block:
 *     {"service_name":"...","size":<bytes>}   ← header JSON (space-padded to fixed width)
 *     <size bytes of raw service data>        ← plain JSON or gzip-compressed TAR
 *
 * Returns a structured parseResult object consumed by the compliance engine.
 */

// ── INI parser ─────────────────────────────────────────────────────────────────

function parseIni(text) {
    const sections = {};
    let currentSection = null;
    for (const rawLine of text.split('\n')) {
        const line = rawLine.trim();
        if (line.startsWith('[') && line.endsWith(']')) {
            currentSection = line.slice(1, -1);
            sections[currentSection] = {};
        } else if (currentSection && line.includes('=')) {
            const equalsIndex = line.indexOf('=');
            const key   = line.slice(0, equalsIndex).trim();
            const value = line.slice(equalsIndex + 1).trim();
            sections[currentSection][key] = value;
        }
    }
    return sections;
}

// ── Gzip decompression (browser DecompressionStream API) ──────────────────────

async function decompressGzip(compressedBytes) {
    const stream  = new DecompressionStream('gzip');
    const writer  = stream.writable.getWriter();
    const reader  = stream.readable.getReader();

    writer.write(compressedBytes);
    writer.close();

    const chunks = [];
    let done = false;
    while (!done) {
        const result = await reader.read();
        done = result.done;
        if (!done) chunks.push(result.value);
    }

    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const decompressedBytes = new Uint8Array(totalLength);
    let writeOffset = 0;
    for (const chunk of chunks) {
        decompressedBytes.set(chunk, writeOffset);
        writeOffset += chunk.length;
    }
    return decompressedBytes;
}

// ── Service block extraction ───────────────────────────────────────────────────

/**
 * Parse the raw UGB bytes and return a Map of service_name → Uint8Array (raw data).
 */
function extractServiceBlocks(fileBytes) {
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    const services = new Map();

    let searchOffset = 0;

    while (searchOffset < fileBytes.length) {
        // Find next service header
        let headerStart = -1;
        for (let i = searchOffset; i < fileBytes.length - 15; i++) {
            if (fileBytes[i] === 0x7B) { // '{'
                const candidate = textDecoder.decode(fileBytes.subarray(i, i + 16));
                if (candidate.startsWith('{"service_name"')) {
                    headerStart = i;
                    break;
                }
            }
        }
        if (headerStart === -1) break;

        // Find end of header JSON
        let depth = 0;
        let headerEnd = headerStart;
        for (let i = headerStart; i < Math.min(headerStart + 512, fileBytes.length); i++) {
            if (fileBytes[i] === 0x7B) depth++;
            else if (fileBytes[i] === 0x7D) {
                depth--;
                if (depth === 0) { headerEnd = i + 1; break; }
            }
        }

        let serviceHeader;
        try {
            serviceHeader = JSON.parse(textDecoder.decode(fileBytes.subarray(headerStart, headerEnd)));
        } catch (_) {
            searchOffset = headerStart + 1;
            continue;
        }

        const { service_name: serviceName, size: dataSize } = serviceHeader;
        if (!serviceName || typeof dataSize !== 'number') {
            searchOffset = headerStart + 1;
            continue;
        }

        // Skip whitespace padding between header and data
        let dataStart = headerEnd;
        while (dataStart < fileBytes.length && (fileBytes[dataStart] === 0x20 || fileBytes[dataStart] === 0x0A || fileBytes[dataStart] === 0x0D || fileBytes[dataStart] === 0x00)) {
            dataStart++;
        }

        const serviceData = fileBytes.slice(dataStart, dataStart + dataSize);
        services.set(serviceName, serviceData);

        searchOffset = dataStart + dataSize;
    }

    return services;
}

// ── Service decoders ───────────────────────────────────────────────────────────

function decodeJsonService(services, serviceName) {
    const rawData = services.get(serviceName);
    if (!rawData) return null;
    try {
        const textDecoder = new TextDecoder('utf-8');
        return JSON.parse(textDecoder.decode(rawData));
    } catch (_) {
        return null;
    }
}

async function decodeTarService(services, serviceName) {
    const rawData = services.get(serviceName);
    if (!rawData) return [];
    try {
        const decompressedBytes = await decompressGzip(rawData);
        return parseTar(decompressedBytes);
    } catch (_) {
        return [];
    }
}

function findTarEntry(tarEntries, filePathSuffix) {
    const entry = tarEntries.find(e => e.name.endsWith(filePathSuffix));
    if (!entry) return null;
    return new TextDecoder('utf-8', { fatal: false }).decode(entry.data);
}

function findTarEntryJson(tarEntries, filePathSuffix) {
    const text = findTarEntry(tarEntries, filePathSuffix);
    if (!text) return null;
    try { return JSON.parse(text); } catch (_) { return null; }
}

// ── Sub-config extractors ──────────────────────────────────────────────────────

function extractTerminalConfig(tarEntries) {
    const iniText = findTarEntry(tarEntries, 'terminal_custom');
    if (!iniText) return null;
    const sections = parseIni(iniText);
    return {
        ssh: {
            enable:              parseInt(sections.ssh?.enable ?? '2', 10),
            permitLanAccessOnly: parseInt(sections.ssh?.permit_lan_access_only ?? '2', 10),
            encryptLevel:        parseInt(sections.ssh?.encrypt_level ?? '0', 10),
        },
        telnet: {
            enable: parseInt(sections.telnet?.enable ?? '2', 10),
        },
    };
}

function extractFirewallConfig(tarEntries) {
    const iniText = findTarEntry(tarEntries, 'globe.ini');
    if (!iniText) return null;
    const sections = parseIni(iniText);
    return {
        firewallEnabled: parseInt(sections.firewall?.enable ?? '0', 10) === 1,
        dosEnabled:      parseInt(sections.firewall?.dos    ?? '0', 10) === 1,
    };
}

function extractUserConfig(tarEntries) {
    const passwordPolicy = findTarEntryJson(tarEntries, 'password-policy.json');
    const passwordExpiry = findTarEntryJson(tarEntries, 'passwd.config');
    return { passwordPolicy, passwordExpiry };
}

function extractUpdateConfig(tarEntries) {
    return findTarEntryJson(tarEntries, 'system.json');
}

// ── Main pipeline ──────────────────────────────────────────────────────────────

/**
 * Parse a UGREEN .ugb backup file and return a structured parseResult.
 *
 * @param {File} file
 * @returns {Promise<Object>} parseResult
 */
async function parseUGBFile(file) {
    const buffer    = await file.arrayBuffer();
    const fileBytes = new Uint8Array(buffer);
    const textDecoder = new TextDecoder('utf-8', { fatal: false });

    // Validate version header
    const firstNewline = fileBytes.indexOf(0x0A);
    if (firstNewline === -1) throw new Error('Invalid .ugb file: no version header');
    const versionLine = textDecoder.decode(fileBytes.subarray(0, firstNewline)).trim();
    if (!versionLine.startsWith('Version:')) {
        throw new Error(`Invalid .ugb file: unexpected header "${versionLine}"`);
    }

    // Parse metadata JSON (first JSON block after version line)
    let metadataStart = firstNewline + 1;
    while (metadataStart < fileBytes.length && fileBytes[metadataStart] !== 0x7B) metadataStart++;

    let depth = 0;
    let metadataEnd = metadataStart;
    for (let i = metadataStart; i < Math.min(metadataStart + 2048, fileBytes.length); i++) {
        if (fileBytes[i] === 0x7B) depth++;
        else if (fileBytes[i] === 0x7D) {
            depth--;
            if (depth === 0) { metadataEnd = i + 1; break; }
        }
    }

    let metadata = {};
    try {
        metadata = JSON.parse(textDecoder.decode(fileBytes.subarray(metadataStart, metadataEnd)));
    } catch (_) {}

    // Extract all service blocks
    const services = extractServiceBlocks(fileBytes);

    // Decode plain JSON services
    const sambaConfig  = decodeJsonService(services, 'com.ugreen.pro.system.filemgr.samba');
    const ftpConfig    = decodeJsonService(services, 'com.ugreen.pro.system.filemgr.ftp');
    const rsyncConfig  = decodeJsonService(services, 'com.ugreen.pro.system.filemgr.rsync');
    const webdavConfig = decodeJsonService(services, 'com.ugreen.pro.system.filemgr.webdav');
    const nfsConfig    = decodeJsonService(services, 'com.ugreen.pro.system.filemgr.nfs');

    // Decode gzip-TAR services
    const terminalTar = await decodeTarService(services, 'com.ugreen.pro.system.terminalmgr');
    const firewallTar = await decodeTarService(services, 'com.ugreen.pro.system.securitymgr.firewall');
    const userTar     = await decodeTarService(services, 'com.ugreen.pro.system.usermgr');
    const updateTar   = await decodeTarService(services, 'com.ugreen.pro.system.updatemgr');

    const terminalConfig = extractTerminalConfig(terminalTar);
    const firewallConfig = extractFirewallConfig(firewallTar);
    const userConfig     = extractUserConfig(userTar);
    const updateConfig   = extractUpdateConfig(updateTar);

    return {
        fileName:       file.name,
        fileSize:       file.size,
        metadata,
        sambaConfig,
        ftpConfig,
        rsyncConfig,
        webdavConfig,
        nfsConfig,
        terminalConfig,
        firewallConfig,
        userConfig,
        updateConfig,
    };
}
