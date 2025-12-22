# hulud-party-scanner

> Project integrity scanner for known vulnerabilities and suspicious patterns related to the Shai-Hulud supply-chain attack.

This tool helps developers identify potential compromises by scanning for signatures associated with the Shai-Hulud supply-chain attack.

It is a **Node.js implementation** based on the original shell script from [sngular/shai-hulud-integrity-scanner](https://github.com/sngular/shai-hulud-integrity-scanner).

## 🚀 Features

- **Pattern Detection**: Scans for known malicious file patterns and content.
- **Cross-Platform**: Runs on Windows, macOS, and Linux via Node.js.
- **Zero Config**: Works out of the box with `npx`.
- **Live IOCs**: Fetches the latest indicators of compromise (hashes, filenames, patterns) at runtime.

## 🔍 What it Scans

Based on the analysis logic in `scan.js`, this tool performs the following checks:

### 1. Dependency Integrity
- **Lockfile Analysis**: Parses `package-lock.json`, `yarn.lock` (v1), and `pnpm-lock.yaml` to detect specific versions of libraries known to be compromised.
- **Deep Node Modules Scan**: Crawls `node_modules` to find installed packages that might not be in the lockfile and checks for suspicious directory names.

### 2. Static Code Analysis & Heuristics
- **Malicious Signatures**: Compares file hashes (SHA256) and filenames against a database of known threats.
- **Behavioral Patterns**: Scans source files (`.js`, `.ts`, `.json`, `.sh`, `.yml`) for suspicious code:
  - **Credential Access**: Usage of `process.env` or patterns matching sensitive keys.
  - **System Discovery**: Calls to `os.platform()`, `os.userInfo()`, or CI environment variables (`GITHUB_ACTIONS`, `CI`).
  - **Execution**: Usage of `child_process`, `exec`, or `spawn`.
  - **Workflow Tampering**: Suspicious `npm publish` or `git push` commands inside `.github/workflows`.

### 3. Lifecycle Hooks
- Inspects `package.json` scripts (`preinstall`, `postinstall`, etc.) for malicious commands or obfuscated scripts.

### 4. Environment Artifacts
- Scans the user's home directory for known malware artifacts (e.g., fake `trufflehog` binaries or caches).

### 5. Risk Assessment
- Maps findings to **MITRE ATT&CK** tactics and calculates a risk score (Low to Critical) based on the correlation of findings.

## 🛠 Usage

You can run the scanner against your current project directory or specify a path.

### Scan Current Directory

```bash
npx hulud-party-scanner
```

To scan a specific directory:
```bash
npx hulud-party-scanner "/path/to/your/project"
```
