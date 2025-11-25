#!/usr/bin/env node
const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

// --- Configuration ---
const COMPROMISED_LIST_URL = "https://raw.githubusercontent.com/migohe14/hulud-scanner/refs/heads/main/compromised-libs.txt";
const MALICIOUS_HASHES = new Set([
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b",
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee",
]);
const COMPROMISED_NAMESPACES = [
    "@crowdstrike", "@art-ws", "@ngx", "@ctrl", "@nativescript-community",
    "@ahmedhfarag", "@operato", "@teselagen", "@things-factory", "@hestjs",
    "@nstudio", "@basic-ui-components-stc", "@nexe", "@thangved",
    "@tnf-dev", "@ui-ux-gang", "@yoobic"
];
const EXFIL_PATTERNS = ['webhook.site', 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', 'exfiltrat'];
const ENV_PATTERNS = ['process\\.env', 'os\\.environ', 'getenv', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN'];
const MALICIOUS_FILENAMES = new Set([
    'bun_environment.js',
    'trufflehog',
    'trufflehog.exe'
]);
const MALICIOUS_COMMAND_PATTERNS = [
    'bun.sh/install', // Catches both curl and powershell variants
    'del /F /Q /S "%USERPROFILE%\\*"',
    'shred -uvz -n 1',
    'cipher /W:%USERPROFILE%'
];

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
 * Downloads the list of compromised packages from GitHub.
 * @returns {Promise<Set<string>>} A Set of packages in "name@version" format.
 */
async function getCompromisedPackages() {
    log.info("Downloading compromised packages list...");
    return new Promise((resolve, reject) => {
        https.get(COMPROMISED_LIST_URL, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                const packages = data
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#')) // Ignore comments and empty lines
                    .map(line => line.replace(':', '@')); // Change 'pkg:1.0.0' to 'pkg@1.0.0'
                resolve(packages);
            });
        }).on('error', (err) => {
            reject(new Error(`Failed to download list: ${err.message}`));
        });
    });
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
 * Parses dependencies from package.json as a fallback.
 * @param {string} pkgJsonPath Path to package.json.
 * @returns {Set<string>} A Set of local dependencies.
 */
function parsePackageJson(pkgJsonPath) {
    log.warn("No lockfile found. Falling back to package.json (will miss transitive dependencies).");
    log.info("Scanning package.json...");
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    const packages = new Set();
    const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    for (const [name, version] of Object.entries(allDeps)) {
        packages.add(`${name}@${version.replace(/[\^~]/g, '')}`);
    }
    return packages;
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
 * Recursively finds all files in a directory, ignoring node_modules, .git, and binary-like extensions.
 * @param {string} directory - The directory to scan.
 * @returns {string[]} A list of file paths.
 */
function getAllFiles(directory) {
    const filesToScan = [];
    const ignoredDirs = new Set(['node_modules', '.git']);
    const ignoredExtensions = new Set(['.md', '.d.ts', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.eot', '.ttf', '.ico']);

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
                filesToScan.push(fullPath);
            }
        }
    }

    findFiles(directory);

    return filesToScan.filter(file => !ignoredExtensions.has(path.extname(file)));
}

/**
 * Scans a list of files for multiple types of threats.
 * @param {string[]} allFiles - A list of absolute file paths to scan.
 * @param {string} projectRoot - The root directory of the project for relative paths.
 * @returns {object} An object containing arrays of different findings.
 */
function scanProjectFiles(allFiles, projectRoot) {
    log.info(`Scanning ${allFiles.length} project files for malicious indicators...`);

    const findings = {
        hashMatches: [],
        namespaceMatches: new Set(),
        hookMatches: [],
        correlatedExfil: [],
        filenameMatches: [],
        commandMatches: [],
    };

    const pkgJsonFiles = allFiles.filter(f => path.basename(f) === 'package.json');

    // Scan for compromised namespaces and postinstall hooks in package.json files
    log.info("Checking for compromised namespaces and package.json hooks...");
    for (const file of pkgJsonFiles) {
        try {
            const content = fs.readFileSync(file, 'utf-8');
            const pkg = JSON.parse(content);

            // Check namespaces
            const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
            for (const depName in allDeps) {
                const namespace = depName.split('/')[0];
                if (COMPROMISED_NAMESPACES.includes(namespace)) {
                    findings.namespaceMatches.add(`Warning: Contains packages from compromised namespace: ${namespace} (Found in ${path.relative(projectRoot, file)})`);
                }
            }

            // Check for postinstall hooks
            if (pkg.scripts && pkg.scripts.postinstall) {
                findings.hookMatches.push(`File: ${path.relative(projectRoot, file)}`);
            }
        } catch (e) {
            log.warn(`Could not parse ${path.relative(projectRoot, file)}: ${e.message}`);
        }
    }

    // Scan file contents for hashes and exfiltration patterns
    log.info("Scanning file signatures and for exfiltration patterns...");
    const envRegex = new RegExp(ENV_PATTERNS.join('|'));
    const exfilRegex = new RegExp(EXFIL_PATTERNS.join('|'));
    const commandRegex = new RegExp(MALICIOUS_COMMAND_PATTERNS.join('|').replace(/%/g, '%').replace(/\*/g, '\\*'), 'i');

    for (const file of allFiles) {
        try {
            const fileBuffer = fs.readFileSync(file);

            // 1. Check hash
            const hashSum = crypto.createHash('sha256');
            hashSum.update(fileBuffer);
            const hex = hashSum.digest('hex');

            if (MALICIOUS_HASHES.has(hex)) {
                findings.hashMatches.push(path.relative(projectRoot, file));
            }

            // 2. Check filename
            if (MALICIOUS_FILENAMES.has(path.basename(file))) {
                findings.filenameMatches.push(path.relative(projectRoot, file));
            }

            // 3. Check for correlated exfiltration and malicious commands (only for text files)
            if (file.endsWith('.js') || file.endsWith('.ts') || file.endsWith('.json') || file.endsWith('.sh') || file.endsWith('.yml')) {
                const content = fileBuffer.toString('utf-8');
                const hasEnv = envRegex.test(content);
                const hasExfil = exfilRegex.test(content);

                // Check for malicious commands
                if (commandRegex.test(content)) {
                    findings.commandMatches.push(path.relative(projectRoot, file));
                }

                if (hasEnv && hasExfil) {
                    findings.correlatedExfil.push(path.relative(projectRoot, file));
                }
            }
        } catch (e) {
            // Ignore errors for files that might be deleted during scan, etc.
        }
    }

    log.info("File scanning complete.");
    return findings;
}

/**
 * Orchestrates the dependency analysis.
 * @param {string} projectRoot The root of the project.
 * @returns {Promise<Set<string>>} A set of matched compromised dependencies.
 */
async function runDependencyAnalysis(projectRoot) {
    log.header("Module 1: Dependency Analysis");
    const pnpmLockFile = path.join(projectRoot, 'pnpm-lock.yaml');
    const yarnLockFile = path.join(projectRoot, 'yarn.lock');
    const npmLockFile = path.join(projectRoot, 'package-lock.json');
    const pkgFile = path.join(projectRoot, 'package.json');

    if (!fs.existsSync(pkgFile)) {
        log.warn("No package.json found. Skipping all dependency analysis.");
        return new Set();
    }

    let localPackages = new Set();
    if (fs.existsSync(pnpmLockFile) && commandExists('pnpm')) {
        localPackages = parsePnpmLock(projectRoot);
    } else if (fs.existsSync(yarnLockFile) && commandExists('yarn')) {
        // Simple check for Yarn v1. Modern yarn doesn't use `yarn list` in the same way.
        const yarnVersion = execSync('yarn --version', { encoding: 'utf8' });
        if (yarnVersion.startsWith('1.')) {
            localPackages = getLocalPackages(yarnLockFile);
        } else {
            log.warn("Modern Yarn (v2+) detected. This script's dependency analysis for Yarn currently only supports v1. Skipping.");
        }
    } else if (fs.existsSync(npmLockFile)) {
        localPackages = getLocalPackages(npmLockFile);
    } else {
        localPackages = parsePackageJson(pkgFile);
    }

    if (localPackages.size === 0) {
        log.warn("Could not determine local packages. Skipping version check.");
        return new Set();
    }

    log.info("Checking for vulnerable versions...");
    const compromisedPackages = new Set(await getCompromisedPackages());
    const matches = new Set();
    for (const localPkg of localPackages) {
        if (compromisedPackages.has(localPkg)) {
            matches.add(localPkg);
        }
    }
    log.info("Dependency analysis complete.");
    return matches;
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

        // --- Run Analyses ---
        const dependencyMatches = await runDependencyAnalysis(projectRoot);

        log.header("Module 2: Project Structure & Content Analysis");
        const allFiles = getAllFiles(projectRoot);
        const fileScanFindings = scanProjectFiles(allFiles, projectRoot);
        const homeDirFindings = scanHomeDirectory();

        // --- Reporting ---
        log.header("Scan Report");
        let issuesFound = false;
        let report = "";

        if (fileScanFindings.hashMatches.length > 0) {
            issuesFound = true;
            report += `${colors.RED}🚨 CRITICAL RISK: Known Malware Signature Detected${colors.RESET}\n`;
            fileScanFindings.hashMatches.forEach(match => {
                report += `   - File with matching signature: ${colors.YELLOW}${match}${colors.RESET}\n`;
            });
            report += "   NOTE: This is a definitive indicator of compromise. Immediate investigation is required.\n\n";
        }

        if (homeDirFindings.length > 0) {
            issuesFound = true;
            report += `${colors.RED}🚨 HIGH RISK: Malicious Artifacts Found in Home Directory${colors.RESET}\n`;
            homeDirFindings.forEach(match => {
                report += `   - ${colors.YELLOW}${match}${colors.RESET}\n`;
            });
            report += "   NOTE: These artifacts are used to store and execute malicious tools.\n\n";
        }

        if (fileScanFindings.filenameMatches.length > 0) {
            issuesFound = true;
            report += `${colors.RED}🚨 HIGH RISK: Known Malicious Filename Detected${colors.RESET}\n`;
            fileScanFindings.filenameMatches.forEach(match => {
                report += `   - File: ${colors.YELLOW}${match}${colors.RESET}\n`;
            });
            report += "   NOTE: These filenames are associated with malicious scripts.\n\n";
        }

        if (fileScanFindings.correlatedExfil.length > 0) {
            issuesFound = true;
            report += `${colors.RED}🚨 HIGH RISK: Environment Scanning with Exfiltration Detected${colors.RESET}\n`;
            fileScanFindings.correlatedExfil.forEach(match => {
                report += `   - File: ${colors.YELLOW}${match}${colors.RESET}\n`;
            });
            report += "   NOTE: These files access secrets AND contain data exfiltration patterns.\n\n";
        }

        if (dependencyMatches.size > 0) {
            issuesFound = true;
            report += `${colors.RED}🚨 HIGH RISK: Compromised Package Versions Detected${colors.RESET}\n`;
            dependencyMatches.forEach(match => {
                report += `   - Package: ${colors.YELLOW}${match}${colors.RESET}\n`;
            });
            report += "   NOTE: These specific package versions are known to be compromised.\n\n";
        }

        if (fileScanFindings.namespaceMatches.size > 0) {
            issuesFound = true;
            report += `${colors.YELLOW}⚠️ MEDIUM RISK: Packages from Compromised Namespaces${colors.RESET}\n`;
            fileScanFindings.namespaceMatches.forEach(match => {
                report += `   - ${match}\n`;
            });
            report += "   NOTE: Review packages from these organizations carefully.\n\n";
        }

        if (fileScanFindings.hookMatches.length > 0) {
            issuesFound = true;
            report += `${colors.YELLOW}⚠️ MEDIUM RISK: Potentially Malicious package.json Hooks${colors.RESET}\n`;
            fileScanFindings.hookMatches.forEach(match => {
                report += `   - ${match}\n`;
            });
            report += "   NOTE: 'postinstall' scripts can execute arbitrary commands and require review.\n\n";
        }

        if (fileScanFindings.commandMatches.length > 0) {
            issuesFound = true;
            report += `${colors.YELLOW}⚠️ MEDIUM RISK: Suspicious Commands Found in Files${colors.RESET}\n`;
            fileScanFindings.commandMatches.forEach(match => {
                report += `   - File: ${colors.YELLOW}${match}${colors.RESET}\n`;
            });
            report += "   NOTE: These files contain commands known to be used for malicious purposes.\n\n";
        }

        if (issuesFound) {
            console.log(report);
            log.error("Scan complete. Actionable issues were found.");
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