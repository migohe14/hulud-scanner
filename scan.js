#!/usr/bin/env node
const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

// --- Configuration ---
const IOC_URLS = {
    COMPROMISED_LIBS: "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/compromised-libs.txt",
    ENV_PATTERNS: "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/env-patterns.txt",
    EXFIL_PATTERNS: "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/exfil-patterns.txt",
    MALICIOUS_COMMANDS: "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/malicious-commands.txt",
    MALICIOUS_FILENAMES: "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/malicious-filenames.txt",
    MALICIOUS_HASHES: "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/malicious-hashes.txt"
};

// --- MITRE ATT&CK & Scoring Configuration ---
const MITRE_ATTACK = {
    "T1064": { name: "Scripting", tactic: "Execution", baseScore: 5 },
    "T1552": { name: "Unsecured Credentials", tactic: "Credential Access", baseScore: 6 },
    "T1082": { name: "System Information Discovery", tactic: "Discovery", baseScore: 3 },
    "T1518": { name: "Software Discovery", tactic: "Discovery", baseScore: 3 },
    "T1053": { name: "Scheduled Task/Job", tactic: "Persistence", baseScore: 8 },
    "T1098": { name: "Account Manipulation", tactic: "Persistence", baseScore: 7 },
    "T1059": { name: "Command and Scripting Interpreter", tactic: "Execution", baseScore: 6 },
    "T1027": { name: "Obfuscated Files or Information", tactic: "Defense Evasion", baseScore: 5 },
    "T1195": { name: "Supply Chain Compromise", tactic: "Initial Access", baseScore: 25 }, // IOC Match
    "T1567": { name: "Exfiltration Over Web Service", tactic: "Exfiltration", baseScore: 9 },
    "T1548": { name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation", baseScore: 9 }
};

// --- Console Colors ---
const colors = {
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    BLUE: '\x1b[34m',
    BOLD: '\x1b[1m',
    RESET: '\x1b[0m'
};

const log = {
    info: (msg) => console.log(`${colors.GREEN}INFO:${colors.RESET} ${msg}`),
    warn: (msg) => console.warn(`${colors.YELLOW}${colors.BOLD}WARN:${colors.RESET} ${msg}`),
    error: (msg) => console.error(`${colors.RED}${colors.BOLD}ERROR:${colors.RESET} ${msg}`),
    header: (msg) => console.log(`\n${colors.BLUE}${colors.BOLD}--- ${msg} ---${colors.RESET}`),
};

const CRITICAL_PATTERNS = [
    // Remote code execution patterns - limited repetition
    { pattern: /curl\s+[^\s|]{1,500}\s*\|\s*(?:sh|bash|zsh)/i, desc: 'Curl piped to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+[^\s|]{1,500}\s*\|\s*(?:sh|bash|zsh)/i, desc: 'Wget piped to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+[^\s]{1,500}>\s*[^|&\s]+\s*&&\s*(?:sh|bash|chmod)/i, desc: 'Curl download & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+[^\s]{0,200}githubusercontent\.com\/[^\s|]{1,300}\|\s*(?:sh|bash|zsh)/i, desc: 'Pipe raw GitHub content to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+[^\s]{0,200}raw\.githubusercontent\.com\/[^\s|]{1,300}\|\s*(?:sh|bash|zsh)/i, desc: 'Pipe raw GitHub content to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /\b(?:b64|base64)\b[^|]{0,100}\|\s*(?:sh|bash)/i, desc: 'Decode then execute via shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /base64\s+(?:-d|--decode)/i, desc: 'Base64 decoding', indicator: 'OBFUSCATION' },
    { pattern: /\beval\s*\(/, desc: 'Eval statement', indicator: 'CODE_INJECTION' },
    { pattern: /setup_bun/i, desc: 'Shai-Hulud Loader', indicator: 'SHAI_HULUD' },
    { pattern: /bun_environment/i, desc: 'Shai-Hulud Payload', indicator: 'SHAI_HULUD' },
    { pattern: /SHA1HULUD/i, desc: 'Shai-Hulud Signature', indicator: 'SHAI_HULUD' },
    { pattern: /node\s+-e\s+["']require\s*\(\s*["']child_process["']\s*\)/, desc: 'Hidden child_process', indicator: 'CODE_INJECTION' },
    { pattern: /child_process[^)]{0,50}exec[^)]{0,50}\$\(/, desc: 'Shell command via child_process', indicator: 'CODE_INJECTION' },
    { pattern: /\$\(curl/i, desc: 'Subshell curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /`curl/i, desc: 'Backtick curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /bash\s+-c\s+["'][^"']{0,200}curl/i, desc: 'bash -c curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+[^\s]{1,300}-o\s+\S+\s*&&\s*(?:sh|bash|chmod)/i, desc: 'curl save & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+[^\s]{1,300}-O\s+\S+\s*&&\s*(?:sh|bash|chmod)/i, desc: 'wget save & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /require\s*\(\s*["']child_process["']\s*\)\.\s*(?:exec|execSync|spawn|spawnSync)/i, desc: 'Direct child_process call', indicator: 'CODE_INJECTION' },
    { pattern: /\b(?:execSync|spawnSync|execFileSync)\s*\(/, desc: 'Sync process execution', indicator: 'CODE_INJECTION' },
    { pattern: /\.github\/workflows\/discussion\.ya?ml/i, desc: 'GitHub workflow backdoor', indicator: 'PERSISTENCE' },
    { pattern: /docker\s+run\s+[^\n]{0,200}--privileged/i, desc: 'Privileged Docker run', indicator: 'PRIV_ESC' },
    { pattern: /-v\s+\/:\/host\b/i, desc: 'Host mount in container', indicator: 'PRIV_ESC' }
];

class Finding {
    constructor(technique, description, severity, evidence, file) {
        this.technique = technique;
        this.tactic = MITRE_ATTACK[technique]?.tactic || "Unknown";
        this.name = MITRE_ATTACK[technique]?.name || "Unknown";
        this.description = description;
        this.severity = severity;
        this.evidence = evidence;
        this.file = file;
        const multipliers = { "CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5, "WARNING": 0.05 };
        this.score = (MITRE_ATTACK[technique]?.baseScore || 1) * (multipliers[severity] || 1);
    }
}

/**
 * Checks if a command exists on the system.
 * @param {string} cmd The command to check.
 * @returns {boolean} True if the command exists.
 */
function commandExists(cmd) {
    try {
        execSync(process.platform === 'win32' ? `where ${cmd}` : `command -v ${cmd}`, { stdio: 'ignore' });
        return true;
    } catch (e) {
        return false;
    }
}

/** 
 * Fetches a list of strings from a URL, ignoring comments and empty lines.
 * @param {string} url The URL to fetch.
 * @returns {Promise<string[]>} A list of strings.
 */
async function fetchRemoteList(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`Failed to fetch ${url}: Status Code ${res.statusCode}`));
                return;
            }
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                const lines = data
                    .split('\n') // Split into lines
                    .map(line => line.trim()) // Trim whitespace
                    .filter(line => line && !line.startsWith('#')); // Ignore comments and empty lines
                resolve(lines);
            });
        }).on('error', (err) => reject(err));
    });
}

/**
 * Parses the raw lines of the compromised libs file into a list of "name@version".
 * @param {string[]} lines The raw lines from the file.
 * @returns {string[]} Parsed packages.
 */
function parseCompromisedLibs(lines) {
    const allCompromised = [];
    lines.forEach(line => {
        if (line.includes(',=')) {
            // Handles format: "pkg-name,= 1.0.0 || = 2.0.0"
            const [name, versionsPart] = line.split(',=');
            const versions = versionsPart.split('||').map(v => v.replace('=', '').trim());
            versions.forEach(version => {
                if (name && version) allCompromised.push(`${name.trim()}@${version}`);
            });
        } else if (line.includes(':')) {
            // Handles original format: "pkg-name:1.0.0"
            allCompromised.push(line.replace(':', '@'));
        } else if (line.lastIndexOf('@') > 0) {
            // Handles format: "pkg-name@1.0.0" or "@scope/pkg@1.0.0"
            // We check lastIndexOf('@') > 0 to ensure there is a version separator,
            // avoiding cases like just "@scope/pkg" (which implies no specific version).
            allCompromised.push(line);
        }
    });
    return allCompromised;
}

/** 
 * Parses dependencies from pnpm-lock.yaml by shelling out to `pnpm`.
 * @param {string} projectPath The root of the project.
 * @returns {Set<string>} A Set of local dependencies.
 */
function parsePnpmLock(projectPath) {
    log.info("Found pnpm-lock.yaml. Analyzing full dependency tree with PNPM...");
    try {
        const pnpmOutput = execSync('pnpm list --json --prod --dev', { cwd: projectPath, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] });
        const deps = JSON.parse(pnpmOutput);
        const packages = new Set();
        const projects = Array.isArray(deps) ? deps : [deps];
        projects.forEach(project => {
            if (!project.dependencies) return;
            Object.entries(project.dependencies).forEach(([name, details]) => {
                packages.add(`${name}@${details.version}`);
            });
        });
        return packages;
    } catch (e) {
        log.warn("The 'pnpm list' command failed. Please run 'pnpm install'.");
        return new Set();
    }
}

/** 
 * Extracts all dependencies from a package-lock.json file.
 * Supports v1/v2 (npm 6) and v2/v3 (npm 7+) formats.
 * @param {string} lockfilePath - Path to the package-lock.json.
 * @returns {Set<string>} A Set of local dependencies in "name@version" format.
 */
function getLocalPackages(lockfilePath) {
    log.info(`Extracting dependencies from ${path.basename(lockfilePath)}...`);
    if (!fs.existsSync(lockfilePath)) {
        throw new Error(`File not found: ${lockfilePath}`);
    }

    const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'));
    const packages = new Set();

    // Heuristic to check for yarn.lock v1 by looking for a characteristic header
    if (path.basename(lockfilePath) === 'yarn.lock') {
        log.info("Classic Yarn (v1) detected. Using 'yarn list'...");
        try {
            // Yarn v1 `list` is very slow, so we give it more time.
            const yarnOutput = execSync('yarn list --json --no-progress', { cwd: path.dirname(lockfilePath), encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'], timeout: 120000 });
            const data = JSON.parse(yarnOutput);
            if (data.type === 'tree' && data.data && data.data.trees) {
                const extractYarnDeps = (trees) => {
                    trees.forEach(tree => {
                        const [name, version] = tree.name.split('@');
                        if (version) packages.add(`${name}@${version}`);
                        if (tree.children) extractYarnDeps(tree.children);
                    });
                };
                extractYarnDeps(data.data.trees);
            }
            return packages;
        } catch (e) {
            log.warn("The 'yarn list' command failed. The project may have no dependencies installed.");
            return new Set();
        }
    }

    // Modern format (npm 7+), 'packages' key
    if (lockfile.packages) {
        log.info(`Analyzing lockfile format v2/v3 (npm 7+)...`);
        for (const [pkgPath, details] of Object.entries(lockfile.packages)) {
            if (pkgPath && details.version) {
                // La ruta es como "node_modules/express" o "" para el root.
                const name = pkgPath.replace(/^node_modules\//, '');
                if (name) { // Ignorar el paquete raíz del proyecto
                    packages.add(`${name}@${details.version}`);
                }
            }
        }
    }
    // Legacy format (npm 6), 'dependencies' key
    else if (lockfile.dependencies) {
        log.info(`Analyzing lockfile format v1 (npm 6)...`);
        const extractDeps = (deps) => {
            if (!deps) return;
            for (const [name, details] of Object.entries(deps)) {
                if (details.version) {
                    packages.add(`${name}@${details.version}`);
                }
                // Recursively search in sub-dependencies
                if (details.dependencies) {
                    extractDeps(details.dependencies);
                }
            }
        };
        extractDeps(lockfile.dependencies);
    } else {
        throw new Error('Unrecognized package-lock.json format.');
    }

    return packages;
}

/**
 * Scans the node_modules directory to find all installed packages by reading their package.json files.
 * This is a deep scan to find packages that might not be in the lockfile.
 * It also flags directories whose names match known compromised packages, even without a package.json.
 * @param {string} projectRoot - The root of the project.
 * @param {Set<string>} compromisedNames - A Set of names of known compromised packages.
 * @returns {Set<string>} A Set of local dependencies in "name@version" format.
 */
function getPackagesFromNodeModules(projectRoot, compromisedNames) {
    log.info("Performing deep scan of node_modules to find all installed packages...");
    const packages = new Set();
    const initialNodeModulesPath = path.join(projectRoot, 'node_modules');

    function addPackage(pkgJsonPath, packageSet) {
        if (fs.existsSync(pkgJsonPath)) {
            try {
                const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
                if (pkg.name && pkg.version) {
                    packageSet.add(`${pkg.name}@${pkg.version}`);
                    return true;
                }
            } catch (e) { /* Ignore parsing errors */ }
        }
        return false;
    }

    function scanDir(nodeModulesPath) {
        if (!fs.existsSync(nodeModulesPath)) return;

        const directories = fs.readdirSync(nodeModulesPath, { withFileTypes: true });

        for (const dir of directories) {
            const dirPath = path.join(nodeModulesPath, dir.name);
            if (dir.name.startsWith('.')) continue; // Skip hidden dirs like .bin

            if (dir.name.startsWith('@')) { // Scoped package
                if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) continue;
                const scopedDirs = fs.readdirSync(dirPath);
                for (const scopedDir of scopedDirs) {
                    const fullPackageName = `${dir.name}/${scopedDir}`;
                    const packagePath = path.join(dirPath, scopedDir);
                    checkPackageDir(fullPackageName, packagePath, packages);
                }
            } else { // Regular package
                checkPackageDir(dir.name, dirPath, packages);
            }
        }
    }

    function checkPackageDir(name, fullPath, packageSet) {
        const pkgJsonPath = path.join(fullPath, 'package.json');
        if (!addPackage(pkgJsonPath, packageSet) && compromisedNames.has(name)) {
            packageSet.add(`${name}@ (directory found without package.json)`);
        }
        // Recurse into nested node_modules
        const nestedNodeModules = path.join(fullPath, 'node_modules');
        if (fs.existsSync(nestedNodeModules)) {
            scanDir(nestedNodeModules);
        }
    }

    scanDir(initialNodeModulesPath);
    return packages;
}
/**
 * @param {string} directory - The directory to scan.
 * @returns {string[]} A list of file paths.
 */
function getAllFiles(directory) {
    const filesToScan = [];
    // Optimized filtering: Ignore common non-source directories. node_modules is scanned separately.
    const ignoredDirs = new Set(['.git', '.angular', '.next', '.nuxt', 'dist', 'build', 'coverage', 'test', '__tests__', 'examples', 'docs']);
    
    // Extensions to ignore directly
    const ignoredExtensions = new Set(['.md', '.map', '.d.ts', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.eot', '.ttf', '.ico']);

    function findFiles(dir) {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (e) {
            return; // Ignore permission errors
        }

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (!ignoredDirs.has(entry.name)) {
                    findFiles(fullPath);
                }
            } else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                
                // Filter: Ignore .json except package.json
                if (ext === '.json' && entry.name !== 'package.json') {
                    continue;
                }

                if (!ignoredExtensions.has(ext)) {
                    filesToScan.push(fullPath);
                }
            }
        }
    }

    findFiles(directory);

    return filesToScan;
}

/**
 * Scans a list of files for multiple types of threats.
 * @param {string[]} allFiles - A list of absolute file paths to scan.
 * @param {string} projectRoot - The root directory of the project for relative paths.
 * @param {object} iocs - Object containing IOC sets and arrays.
 * @returns {Finding[]} A list of findings.
 */
function scanProjectFiles(allFiles, projectRoot, iocs) {
    log.info(`Scanning ${allFiles.length} project files for malicious indicators...`);

    const findings = [];
    const pkgJsonFiles = allFiles.filter(f => path.basename(f) === 'package.json');
    const commandRegex = new RegExp(iocs.maliciousCommands.join('|').replace(/%/g, '%').replace(/\*/g, '\\*'), 'i');

    // Scan for postinstall hooks in package.json files
    log.info("Checking for package.json hooks...");
    for (const file of pkgJsonFiles) {
        try {
            const content = fs.readFileSync(file, 'utf-8');
            const pkg = JSON.parse(content);

            // Check for postinstall hooks
            if (pkg.scripts) {
                const hooks = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare', 'preuninstall', 'postuninstall'];
                hooks.forEach(hook => {
                    if (pkg.scripts[hook]) {
                        // Only check hooks in root package.json here. node_modules are handled in scanNodeModulesForFiles
                        // Add a low-severity finding for any lifecycle hook to aid in correlation.
                        findings.push(new Finding("T1064", `Lifecycle Hook Detected (${hook})`, "LOW", `Script: ${pkg.scripts[hook]}`, path.relative(projectRoot, file)));
                        if (!file.includes('node_modules') && commandRegex.test(pkg.scripts[hook])) {
                            findings.push(new Finding("T1195", `Malicious Command in Hook (${hook})`, "CRITICAL", `Script: ${pkg.scripts[hook]}`, path.relative(projectRoot, file)));
                        }
                    }
                });
            }
        } catch (e) {
            log.warn(`Could not parse ${path.relative(projectRoot, file)}: ${e.message}`);
        }
    }

    // Scan file contents for hashes and exfiltration patterns
    log.info("Scanning file signatures and for exfiltration patterns...");
    const envRegex = new RegExp(iocs.envPatterns.join('|'));
    const exfilRegex = new RegExp(iocs.exfilPatterns.join('|'));

    const totalFiles = allFiles.length;
    let processedFiles = 0;

    for (const file of allFiles) {
        processedFiles++;
        const percentage = Math.round((processedFiles / totalFiles) * 100);
        const barLength = 40;
        const filledLength = Math.round(barLength * (processedFiles / totalFiles));
        const bar = '█'.repeat(filledLength) + '-'.repeat(barLength - filledLength);
        process.stdout.write(`\r[${bar}] ${percentage}% (${processedFiles}/${totalFiles})`);
        try {
            const fileBuffer = fs.readFileSync(file);

            // 1. Check hash
            const hashSum = crypto.createHash('sha256');
            hashSum.update(fileBuffer);
            const hex = hashSum.digest('hex');

            if (iocs.maliciousHashes.has(hex)) {
                findings.push(new Finding("T1195", "Known Malicious File Hash", "CRITICAL", `Hash: ${hex}`, path.relative(projectRoot, file)));
            }

            // 2. Check filename
            if (iocs.maliciousFilenames.has(path.basename(file))) {
                findings.push(new Finding("T1195", "Known Malicious Filename", "HIGH", `Filename: ${path.basename(file)}`, path.relative(projectRoot, file)));
            }

            // 3. Behavioral Analysis (Text files)
            if (file.endsWith('.js') || file.endsWith('.ts') || file.endsWith('.json') || file.endsWith('.sh') || file.endsWith('.yml')) {
                const content = fileBuffer.toString('utf-8');
                const isInNodeModules = file.includes('node_modules');
                
                // T1552: Unsecured Credentials
                // Ignore config files where process.env is common/expected
                const isConfigFile = /config\.(js|ts|mjs|cjs)$/i.test(file);
                if (!isInNodeModules && (/\bprocess\.env\b/.test(content) || envRegex.test(content)) && !isConfigFile) {
                    findings.push(new Finding("T1552", "Access to Environment Variables", "LOW", "Pattern: process.env or similar", path.relative(projectRoot, file)));
                }

                // T1518: Software Discovery (CI/Runners)
                if (!isInNodeModules && (/\bGITHUB_ACTIONS\b|\bCI\b|\bGITLAB_CI\b/.test(content))) {
                    findings.push(new Finding("T1518", "CI Environment Discovery", "LOW", "Pattern: CI/GITHUB_ACTIONS", path.relative(projectRoot, file)));
                }

                // T1082: System Information Discovery
                if (!isInNodeModules && (/\bos\.platform\(\)|\bos\.userInfo\(\)|\bhomedir\(\)/.test(content))) {
                    findings.push(new Finding("T1082", "System Information Discovery", "LOW", "Pattern: os.platform/userInfo", path.relative(projectRoot, file)));
                }

                // T1059: Command Execution
                if (!isInNodeModules && (/\bchild_process\b|\bexec\s*\(|\bspawn\s*\(|\bexecSync\s*\(/.test(content))) {
                    findings.push(new Finding("T1059", "Process Execution", "MEDIUM", "Pattern: child_process/exec", path.relative(projectRoot, file)));
                }

                // T1053: Persistence via Workflows
                if (!isInNodeModules && file.includes('.github/workflows')) {
                    if (/run:.*npm publish/.test(content) || /run:.*git push/.test(content)) {
                        findings.push(new Finding("T1098", "Suspicious Workflow Action", "HIGH", "Pattern: npm publish/git push in workflow", path.relative(projectRoot, file)));
                    }
                }

                // Advanced Pattern Matching (CRITICAL_PATTERNS)
                for (const check of CRITICAL_PATTERNS) {
                    if (check.pattern.test(content)) {
                        let technique = "T1059"; // Default: Command Execution
                        if (check.indicator === 'OBFUSCATION') technique = "T1027";
                        if (check.indicator === 'SHAI_HULUD') technique = "T1195";
                        if (check.indicator === 'PERSISTENCE') technique = "T1098";
                        if (check.indicator === 'PRIV_ESC') technique = "T1548";
                        const severity = isInNodeModules ? "WARNING" : "CRITICAL";
                        findings.push(new Finding(technique, check.desc, severity, `Pattern match: ${check.desc}`, path.relative(projectRoot, file)));
                    }
                }
            }
        } catch (e) {
            // Ignore errors for files that might be deleted during scan, etc.
        }
    }

    process.stdout.write('\n'); // Salto de línea después de la barra de progreso

    log.info("File scanning complete.");
    return findings;
}

/**
 * Recursively scans the node_modules directory specifically for known malicious filenames.
 * This is a targeted scan for performance reasons.
 * @param {string} nodeModulesPath - The absolute path to the node_modules directory.
 * @param {string} projectRoot - The root directory of the project for relative paths.
 * @param {object} iocs - Object containing IOC sets and arrays.
 * @returns {Finding[]} A list of findings.
 */
function scanNodeModulesForFiles(nodeModulesPath, projectRoot, iocs) {
    if (!fs.existsSync(nodeModulesPath)) {
        return [];
    }
    log.info("Scanning node_modules for malicious filenames and suspicious package.json scripts...");
    const findings = [];
    
    // Regex for malicious commands (same as in scanProjectFiles)
    const commandRegex = new RegExp(iocs.maliciousCommands.join('|').replace(/%/g, '%').replace(/\*/g, '\\*'), 'i');

    function findFiles(dir) {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (e) { return; }

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                findFiles(fullPath);
            } else if (entry.isFile()) {
                if (iocs.maliciousFilenames.has(entry.name)) {
                    findings.push(new Finding("T1195", "Malicious Filename in node_modules", "HIGH", `File: ${entry.name}`, path.relative(projectRoot, fullPath)));
                } else if (entry.name === 'package.json') {
                    // Inspect package.json inside node_modules for malicious commands
                    try {
                        const content = fs.readFileSync(fullPath, 'utf-8');
                        const pkg = JSON.parse(content);
                        if (pkg.scripts) {
                            // Specific Shai-Hulud checks in preinstall
                            if (pkg.scripts.preinstall) {
                                const referencedMaliciousFile = Array.from(iocs.maliciousFilenames).find(f => pkg.scripts.preinstall.includes(f));
                                if (referencedMaliciousFile) {
                                    findings.push(new Finding("T1195", "Shai-Hulud Malware Installer", "CRITICAL", `Reference to known malicious file '${referencedMaliciousFile}' in preinstall: ${pkg.scripts.preinstall}`, path.relative(projectRoot, fullPath)));
                                } else if (/\bbun\s+/.test(pkg.scripts.preinstall)) {
                                    findings.push(new Finding("T1195", "Suspicious 'bun' execution in preinstall", "HIGH", `Script uses bun unexpectedly: ${pkg.scripts.preinstall}`, path.relative(projectRoot, fullPath)));
                                } else if (/(\\x[0-9a-fA-F]{2}){4,}|eval\s*\(/.test(pkg.scripts.preinstall)) {
                                    findings.push(new Finding("T1027", "Obfuscated Script in preinstall", "HIGH", `Potential obfuscation detected`, path.relative(projectRoot, fullPath)));
                                }
                            }
                            // General malicious command check
                            Object.values(pkg.scripts).forEach(script => {
                                if (commandRegex.test(script)) {
                                    findings.push(new Finding("T1195", "Malicious Command in Dependency", "WARNING", `Pattern match: ${script}`, path.relative(projectRoot, fullPath)));
                                }
                            });

                            // Check for compromised packages listed as dependencies
                            const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}) };
                            Object.entries(allDeps).forEach(([depName, depVersion]) => {
                                // Simple version cleaning. This is a best-effort check.
                                const cleanedVersion = depVersion.replace(/[\^~>=<]/g, '');
                                const depIdentifier = `${depName}@${cleanedVersion}`;
                                
                                if (iocs.compromisedPackages.has(depIdentifier)) {
                                    const evidence = `Package '${pkg.name}@${pkg.version}' lists a compromised dependency: '${depIdentifier}'`;
                                    findings.push(new Finding(
                                        "T1195", "Compromised Dependency in node_modules", "CRITICAL", evidence, path.relative(projectRoot, fullPath)
                                    ));
                                }
                            });
                        }
                    } catch (e) { /* ignore read errors */ }
                }
            }
        }
    }

    findFiles(nodeModulesPath);
    return findings;
}
/**
 * Scans the user's home directory for known malicious artifacts.
 * @returns {Finding[]} A list of findings.
 */
function scanHomeDirectory() {
    log.info("Scanning user home directory for known artifacts...");
    const homeDir = require('os').homedir();
    const findings = [];
    const truffleCachePath = path.join(homeDir, '.truffler-cache');

    if (fs.existsSync(truffleCachePath)) {
        findings.push(new Finding("T1552", "Malicious Artifact (Trufflehog Cache)", "HIGH", `Path: ${truffleCachePath}`, "HOME_DIR"));
        // Also check for the specific binaries inside
        const trufflehogPath = path.join(truffleCachePath, 'trufflehog');
        const trufflehogExePath = path.join(truffleCachePath, 'trufflehog.exe');
        if (fs.existsSync(trufflehogPath)) {
            findings.push(new Finding("T1552", "Malicious Binary (Trufflehog)", "HIGH", `Path: ${trufflehogPath}`, "HOME_DIR"));
        }
        if (fs.existsSync(trufflehogExePath)) {
            findings.push(new Finding("T1552", "Malicious Binary (Trufflehog.exe)", "HIGH", `Path: ${trufflehogExePath}`, "HOME_DIR"));
        }
    }
    return findings;
}
/**
 * Orchestrates the dependency analysis.
 * @param {string} projectRoot The root of the project.
 * @param {Set<string>} compromisedPackagesWithVersions - Set of known compromised packages.
 * @returns {Promise<Finding[]>} A list of findings.
 */
async function runDependencyAnalysis(projectRoot, compromisedPackagesWithVersions) {
    log.header("Module 1: Dependency Analysis");
    const pnpmLockFile = path.join(projectRoot, 'pnpm-lock.yaml');
    const yarnLockFile = path.join(projectRoot, 'yarn.lock');
    const npmLockFile = path.join(projectRoot, 'package-lock.json');
    const pkgFile = path.join(projectRoot, 'package.json');

    if (!fs.existsSync(pkgFile)) {
        log.warn("No package.json found. Skipping all dependency analysis.");
        return [];
    }

    let localPackages = new Set();
    let lockfileFound = false;

    // Always parse package.json for top-level dependencies.
    // This is crucial for catching malicious packages added to package.json before `npm install` is run.
    try {
        const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf-8'));
        const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}) };
        log.info("Scanning package.json for declared dependencies...");
        for (const [name, version] of Object.entries(allDeps)) {
            // This is a simple version cleaner. It won't resolve complex ranges but is essential for this check.
            localPackages.add(`${name}@${version.replace(/[\^~>=<]/g, '')}`);
        }
    } catch (e) {
        log.warn(`Could not parse ${pkgFile}. Skipping manifest analysis.`);
    }

    // Now, parse the lockfile for the full dependency tree if it exists. The Set will handle duplicates.
    if (fs.existsSync(pnpmLockFile) && commandExists('pnpm')) {
        lockfileFound = true;
        const pnpmPkgs = parsePnpmLock(projectRoot);
        pnpmPkgs.forEach(pkg => localPackages.add(pkg));
    } else if (fs.existsSync(yarnLockFile) && commandExists('yarn')) {
        // Simple check for Yarn v1. Modern yarn doesn't use `yarn list` in the same way.
        const yarnVersion = execSync('yarn --version', { encoding: 'utf8' });
        if (yarnVersion.startsWith('1.')) {
            lockfileFound = true;
            const yarnPkgs = getLocalPackages(yarnLockFile);
            yarnPkgs.forEach(pkg => localPackages.add(pkg));
        } else {
            log.warn("Modern Yarn (v2+) detected. Lockfile analysis for Yarn v1 only. Relying on package.json.");
        }
    } else if (fs.existsSync(npmLockFile)) {
        lockfileFound = true;
        const npmPkgs = getLocalPackages(npmLockFile);
        npmPkgs.forEach(pkg => localPackages.add(pkg));
    }

    if (!lockfileFound) {
        log.warn("No lockfile found. Analysis is based on package.json and may miss transitive dependencies.");
    }

    // Create a set of just the names for directory matching
    const compromisedPackageNames = new Set(Array.from(compromisedPackagesWithVersions).map(pkg => {
        const lastAt = pkg.lastIndexOf('@');
        return lastAt > 0 ? pkg.substring(0, lastAt) : pkg.split('@')[0];
    }));

    // Perform a deep scan of node_modules to verify installed versions
    const installedPackages = getPackagesFromNodeModules(projectRoot, compromisedPackageNames);
    const findings = [];
    const reportedPackages = new Set(); // Track reported packages to avoid duplicates

    // Priority: Check installed packages in node_modules
    if (installedPackages.size > 0) {
        log.info(`Verifying ${installedPackages.size} installed packages against compromised list...`);
        for (const localPkg of installedPackages) {
            const isMissingPkgJson = localPkg.includes('(directory found without package.json)');
            
            if (compromisedPackagesWithVersions.has(localPkg)) {
                reportedPackages.add(localPkg); // Mark this exact version as reported
                // Exact match of Name + Version in node_modules/package.json
                let evidence = `Package: ${localPkg}\n    IOC Source: ${IOC_URLS.COMPROMISED_LIBS}`;
                const lastAt = localPkg.lastIndexOf('@');
                if (lastAt > 0) {
                    const name = localPkg.substring(0, lastAt);
                    const localPath = path.join(projectRoot, 'node_modules', name, 'package.json');
                    evidence += `\n    File: ${localPath}`;
                }
                findings.push(new Finding("T1195", "Compromised Package Version", "CRITICAL", evidence, "node_modules"));
            } else if (isMissingPkgJson) {
                findings.push(new Finding("T1195", "Suspicious Package Directory (Compromised Name)", "CRITICAL", `Directory with compromised name found: ${localPkg}. The package version could not be verified.`, "node_modules"));
            }
        }
    } else if (localPackages.size > 0) {
        // Fallback: Check lockfiles/manifests if node_modules is missing
        log.warn("node_modules not scanned. Falling back to lockfile/manifest analysis.");
    }
    // Fallback: Check lockfiles/manifests for packages not already reported from node_modules
    if (localPackages.size > 0) {
        log.info("Verifying packages from lockfile/manifest...");
        for (const localPkg of localPackages) {
            if (reportedPackages.has(localPkg)) {
                continue; // Already reported with CRITICAL severity from node_modules
            }
            if (compromisedPackagesWithVersions.has(localPkg)) {
                findings.push(new Finding("T1195", "Compromised Package Version in Manifest", "CRITICAL", `Package: ${localPkg}\n    Source: Lockfile/Manifest (Not installed or verified on disk)`, "package.json/lockfile"));
            }
        }
    }
    log.info("Dependency analysis complete.");
    return findings;
}

/**
 * Calculates the final score and verdict based on findings and correlations.
 * @param {Finding[]} findings 
 */
function calculateRisk(findings) {
    let totalScore = 0;
    const techniquesDetected = new Set();
    const tacticsDetected = new Set();
    let hasCritical = false;
    let hasHigh = false;
    let hasShaiHuludIndicator = false;

    // Check for high-confidence indicators and calculate score from actionable findings.
    findings.forEach(f => {
        // Check for specific, high-confidence Shai-Hulud indicators in the finding's text.
        if (/shai-hulud|trufflehog|setup_bun|bun_environment/i.test(f.description) || /shai-hulud|trufflehog|setup_bun|bun_environment/i.test(f.evidence)) {
            hasShaiHuludIndicator = true;
        }

        // Ignore LOW and WARNING for scoring and technique correlation.
        if (f.severity === 'WARNING' || f.severity === 'LOW') return;

        totalScore += f.score;
        techniquesDetected.add(f.technique);
        tacticsDetected.add(f.tactic);
        if (f.severity === 'CRITICAL') hasCritical = true;
        if (f.severity === 'HIGH') hasHigh = true;
    });

    const hasScripting = techniquesDetected.has("T1064"); // Lifecycle hooks
    const hasCredAccess = techniquesDetected.has("T1552"); // process.env
    const hasDiscovery = techniquesDetected.has("T1518") || techniquesDetected.has("T1082"); // CI or Sys info
    const hasExecution = techniquesDetected.has("T1059"); // child_process

    let suspectedFamily = "None";
    let correlationBonus = 0;

    // Rule: T1064 + T1552 + T1518 -> High probability of Shai Hulud
    // A specific indicator like trufflehog is a stronger signal than the behavioral pattern.
    if (hasShaiHuludIndicator || (hasScripting && hasCredAccess && hasDiscovery)) {
        correlationBonus += 50;
        suspectedFamily = "Shai-Hulud (High Confidence)";
    } else if (hasScripting && hasExecution) {
        correlationBonus += 20;
        suspectedFamily = "Generic Malware Loader";
    }

    totalScore += correlationBonus;

    let verdict = "LOW";
    if (totalScore > 80) verdict = "CRITICAL";
    else if (totalScore > 40) verdict = "HIGH";
    else if (totalScore > 15) verdict = "MEDIUM";

    // Safety Cap: Prevent CRITICAL verdict if no actual CRITICAL findings exist
    if (verdict === "CRITICAL" && !hasCritical) {
        verdict = hasHigh ? "HIGH" : "MEDIUM";
    }

    return { totalScore, verdict, suspectedFamily, techniques: Array.from(techniquesDetected) };
}

/** 
 * Main function to orchestrate the scan.
 */
async function main() {
    try {
        // Use the provided path or the current directory.
        const targetPath = process.argv[2] || '.';
        const projectRoot = path.resolve(targetPath);

        if (!fs.existsSync(projectRoot) || !fs.statSync(projectRoot).isDirectory()) {
            throw new Error(`Project directory not found: ${projectRoot}`);
        }

        console.log(`\n${colors.BLUE}${colors.BOLD}--- Shai-Hulud Integrity Scanner (Node.js) ---${colors.RESET}`);
        log.info(`Scanning project at: ${projectRoot}`);

        // --- Fetch IOCs ---
        log.info("Downloading IOC definitions from remote repositories...");
        const [
            compromisedLibsLines,
            maliciousHashes,
            maliciousFilenames,
            maliciousCommands,
            exfilPatterns,
            envPatterns
        ] = await Promise.all([
            fetchRemoteList(IOC_URLS.COMPROMISED_LIBS),
            fetchRemoteList(IOC_URLS.MALICIOUS_HASHES),
            fetchRemoteList(IOC_URLS.MALICIOUS_FILENAMES),
            fetchRemoteList(IOC_URLS.MALICIOUS_COMMANDS),
            fetchRemoteList(IOC_URLS.EXFIL_PATTERNS),
            fetchRemoteList(IOC_URLS.ENV_PATTERNS)
        ]);

        const iocs = {
            maliciousHashes: new Set(maliciousHashes),
            maliciousFilenames: new Set(maliciousFilenames),
            maliciousCommands: maliciousCommands,
            exfilPatterns: exfilPatterns,
            envPatterns: envPatterns,
            compromisedPackages: new Set(parseCompromisedLibs(compromisedLibsLines))
        };

        log.info(`Loaded IOCs: ${iocs.compromisedPackages.size} compromised pkgs, ${iocs.maliciousHashes.size} hashes, ${iocs.maliciousFilenames.size} filenames.`);

        // --- Run Analyses ---
        const allFindings = [];
        
        const dependencyFindings = await runDependencyAnalysis(projectRoot, iocs.compromisedPackages);
        allFindings.push(...dependencyFindings);

        log.header("Module 2: Project Structure & Content Analysis");
        const allFiles = getAllFiles(projectRoot);
        const fileFindings = scanProjectFiles(allFiles, projectRoot, iocs);
        allFindings.push(...fileFindings);

        const homeDirFindings = scanHomeDirectory();
        allFindings.push(...homeDirFindings);

        const nodeModulesFindings = scanNodeModulesForFiles(path.join(projectRoot, 'node_modules'), projectRoot, iocs);
        allFindings.push(...nodeModulesFindings);

        // --- Scoring & Correlation ---
        const riskAssessment = calculateRisk(allFindings);

        // --- Reporting ---
        log.header("Scan Report");
        
        // JSON Output support
        if (process.argv.includes('--json')) {
            console.log(JSON.stringify({
                risk: riskAssessment,
                findings: allFindings
            }, null, 2));
            process.exit(riskAssessment.verdict === 'LOW' ? 0 : 1);
        }

        // Human Readable Output
        console.log(`\n${colors.BOLD}Risk Verdict:${colors.RESET} ${riskAssessment.verdict === 'CRITICAL' || riskAssessment.verdict === 'HIGH' ? colors.RED : riskAssessment.verdict === 'MEDIUM' ? colors.YELLOW : colors.GREEN}${riskAssessment.verdict}${colors.RESET}`);
        console.log(`${colors.BOLD}Total Score:${colors.RESET} ${riskAssessment.totalScore}`);
        console.log(`${colors.BOLD}Suspected Family:${colors.RESET} ${riskAssessment.suspectedFamily}`);
        console.log(`${colors.BOLD}MITRE Techniques:${colors.RESET} ${riskAssessment.techniques.join(', ')}\n`);

        const visibleFindings = allFindings.filter(f => f.severity !== 'WARNING' && f.severity !== 'LOW');
        if (visibleFindings.length > 0) {
            console.log(`${colors.BOLD}Detailed Findings:${colors.RESET}`);
            visibleFindings.sort((a, b) => b.score - a.score).forEach(f => {
                const color = (f.severity === 'CRITICAL' || f.severity === 'HIGH') ? colors.RED : (f.severity === 'MEDIUM' || f.severity === 'WARNING') ? colors.YELLOW : colors.BLUE;
                console.log(`[${color}${f.severity}${colors.RESET}] ${colors.BOLD}${f.technique} - ${f.name}${colors.RESET}`);
                console.log(`    File: ${f.file}`);
                console.log(`    Evidence: ${f.evidence}`);
                console.log(`    Description: ${f.description}\n`);
            });
        }

        if (riskAssessment.verdict !== 'LOW') {
            console.error(`${colors.RED}${colors.BOLD}❌ Scan complete. Potential threats detected.${colors.RESET}`);
            process.exit(2);
        } else {
            log.info(`${colors.GREEN}✅ No actionable project integrity issues found.${colors.RESET}`);
        }

    } catch (error) {
        log.error(error.message);
        process.exit(1);
    }
}

main();