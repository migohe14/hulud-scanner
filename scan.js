#!/usr/bin/env node
const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
 
// --- Configuration ---
const COMPROMISED_LIST_URL = "";
const MALICIOUS_HASH = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09";

// --- Console Colors ---
const colors = {
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    CYAN: '\x1b[36m',
    RESET: '\x1b[0m'
};

/** 
 * Downloads the list of compromised packages from GitHub.
 * @returns {Promise<Set<string>>} A Set of packages in "name@version" format.
 */
async function getCompromisedPackages() {
    console.log(`${colors.CYAN}🌐 Downloading compromised packages list...${colors.RESET}`);
    return new Promise((resolve, reject) => {
        https.get(COMPROMISED_LIST_URL, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                const packages = data
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#')) // Ignore comments and empty lines
                    .map(line => line.replace(':', '@')) // Change 'pkg:1.0.0' to 'pkg@1.0.0'
                    .reduce((acc, line) => {
                        // Handle lines with multiple versions like 'pkg:1.0.0, 1.0.1'
                        const [name, versions] = line.split('@');
                        if (versions) {
                            versions.split(',').forEach(version => {
                                acc.add(`${name}@${version.trim()}`);
                            });
                        }
                        return acc;
                    }, new Set());
                resolve(packages);
            });
        }).on('error', (err) => {
            reject(new Error(`Failed to download list: ${err.message}`));
        });
    });
}

/** 
 * Extracts all dependencies from a package-lock.json file.
 * Supports v1/v2 (npm 6) and v2/v3 (npm 7+) formats.
 * @param {string} lockfilePath - Path to the package-lock.json.
 * @returns {Set<string>} A Set of local dependencies in "name@version" format.
 */
function getLocalPackages(lockfilePath) {
    console.log(`${colors.CYAN}📦 Extracting dependencies from ${lockfilePath}...${colors.RESET}`);
    if (!fs.existsSync(lockfilePath)) {
        throw new Error(`File not found: ${lockfilePath}`);
    }

    const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'));
    const packages = new Set();

    // Modern format (npm 7+), 'packages' key
    if (lockfile.packages) {
        console.log(`🔍 Analyzing lockfile format v2/v3 (npm 7+)...`);
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
        console.log(`🔍 Analyzing lockfile format v1 (npm 6)...`);
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
 * Recursively scans a directory for files matching a known malicious hash.
 * @param {string} directory - The directory to scan.
 * @returns {string[]} A list of paths to malicious files.
 */
function scanForMaliciousFiles(directory) {
    console.log(`${colors.CYAN}🔍 Scanning file signatures in ${directory}...${colors.RESET}`);
    const maliciousFiles = [];
    const filesToScan = [];

    // Get all files recursively, ignoring node_modules and .git
    function findFiles(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (entry.name !== 'node_modules' && entry.name !== '.git') {
                    findFiles(fullPath);
                }
            } else if (entry.isFile()) {
                filesToScan.push(fullPath);
            }
        }
    }

    findFiles(directory);

    for (const file of filesToScan) {
        const fileBuffer = fs.readFileSync(file);
        const hashSum = crypto.createHash('sha256');
        hashSum.update(fileBuffer);
        const hex = hashSum.digest('hex');

        if (hex === MALICIOUS_HASH) {
            maliciousFiles.push(path.relative(directory, file));
        }
    }
    return maliciousFiles;
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

        console.log(`\n${colors.BLUE}--- Shai-Hulud Integrity Scanner (Node.js) ---${colors.RESET}`);
        console.log(`Scanning project at: ${projectRoot}`);

        // --- Vector 1: Dependency Analysis ---
        let dependencyMatches = new Set();
        const lockfilePath = path.join(projectRoot, 'package-lock.json');

        if (fs.existsSync(lockfilePath)) {
            const localPackages = getLocalPackages(lockfilePath);
            const compromisedPackages = await getCompromisedPackages();
            console.log(`${colors.CYAN}🔍 Comparing dependencies...${colors.RESET}`);
            for (const localPkg of localPackages) {
                if (compromisedPackages.has(localPkg)) {
                    dependencyMatches.add(localPkg);
                }
            }
        } else {
            console.log(`${colors.YELLOW}⚠️  No package-lock.json found. Skipping dependency scan.${colors.RESET}`);
        }

        // --- Vector 2: File Signature Analysis ---
        const fileMatches = scanForMaliciousFiles(projectRoot);

        // --- Reporting ---
        console.log('\n' + '-'.repeat(50));
        let issuesFound = false;

        if (fileMatches.length > 0) {
            issuesFound = true;
            console.log(`${colors.RED}🚨 CRITICAL RISK: Known Malware Signature Detected${colors.RESET}`);
            fileMatches.forEach(match => {
                console.log(`  - File: ${colors.YELLOW}${match}${colors.RESET}`);
            });
            console.log('');
        }

        if (dependencyMatches.size > 0) {
            issuesFound = true;
            console.log(`${colors.RED}🚨 HIGH RISK: Compromised Package Versions Detected${colors.RESET}`);
            dependencyMatches.forEach(match => {
                console.log(`  - ${colors.YELLOW}${match}${colors.RESET}`);
            });
        }

        console.log('-'.repeat(50));
        if (issuesFound) {
            console.log(`${colors.RED}Scan complete. Actionable issues were found.${colors.RESET}`);
            process.exit(2);
        } else {
            console.log(`${colors.GREEN}✅ All good! No known integrity issues found.${colors.RESET}`);
        }

    } catch (error) {
        console.error(`${colors.RED}❌ ERROR: ${error.message}${colors.RESET}`);
        process.exit(1);
    }
}

main();