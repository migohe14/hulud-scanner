# hulud-party-scanner

> Project integrity scanner for known vulnerabilities and suspicious patterns related to the **Shai-Hulud supply-chain attack**.

This tool helps developers identify potential compromises by scanning for signatures, behaviors, and indicators associated with the Shai-Hulud supply-chain attack.

It is a **Node.js implementation** inspired by the original shell script from  
[sngular/shai-hulud-integrity-scanner](https://github.com/sngular/shai-hulud-integrity-scanner), extended with deeper static analysis and heuristic detection.

---

## 🚀 Features

- **Pattern Detection**: Scans for known malicious filenames, hashes, and code patterns.
- **Heuristic Analysis**: Detects suspicious behaviors commonly used in supply-chain attacks.
- **Cross-Platform**: Runs on Windows, macOS, and Linux.
- **Zero Config**: Works out of the box via `npx`.
- **Live IOCs**: Fetches the latest indicators of compromise (IOCs) at runtime.
- **Light & Deep Modes**: Choose between fast scans or exhaustive analysis.

---

## 🔍 What It Scans

Based on the logic in `scan.js`, the scanner performs the following checks:

---

### 1. Dependency Integrity

- **Lockfile Analysis**
  - Parses `package-lock.json`, `yarn.lock` (v1), and `pnpm-lock.yaml`
  - Compares declared dependencies against a list of known compromised packages
- **Node Modules Inspection** (`--deep` mode only)
  - Identifies suspicious package names (e.g., a directory with a malicious name but without a `package.json`).
  - Verifies the exact versions of all installed packages by reading their `package.json` files directly from `node_modules`.

> ⚠️ In **deep mode**, the entire `node_modules` tree is recursively scanned.

---

### 2. Static Code Analysis & Heuristics

- **Malicious Signatures**
  - Matches filenames and SHA-256 hashes against known malware databases
- **Behavioral Patterns**
  - Scans `.js`, `.ts`, `.json`, `.sh`, `.yml` files for suspicious code, including:
    - **Credential Access**
      - `process.env`, hard-coded tokens, API keys
    - **System Discovery**
      - `os.platform()`, `os.userInfo()`, CI variables (`CI`, `GITHUB_ACTIONS`)
    - **Command Execution**
      - `child_process`, `exec`, `spawn`
    - **Workflow Tampering**
      - Suspicious `npm publish`, `curl | bash`, or `git push` commands in `.github/workflows`

---

### 3. Package Lifecycle Hooks

- Inspects `package.json` scripts for dangerous commands, including:
  - `preinstall`
  - `install`
  - `postinstall`
  - `prepublish`
  - `prepare`
  - `preuninstall`
  - `postuninstall`
- Detects obfuscated shell commands, network calls (`curl`, `wget`), and execution of bundled binaries within these scripts.

---

### 4. Environment Artifacts

- Scans the user’s home directory for known artifacts linked to Shai-Hulud:
  - Fake binaries (e.g. trojanized `trufflehog`)
  - Suspicious cache directories
  - Residual malware files

---

### 5. Risk Assessment

- Correlates findings across multiple signals
- Maps behaviors to **MITRE ATT&CK** tactics
- Produces a final **risk score**:
  - 🟢 Low
  - 🟡 Medium
  - 🟠 High
  - 🔴 Critical

---

## 🛠 Usage

The scanner supports two modes:

- **Light scan** (default): fast, low-overhead, manifest-based
- **Deep scan** (`--deep`): exhaustive filesystem and dependency analysis

---

### ⚡ Light Scan (Default)
**What it does:**
- Analyzes `package.json` for declared dependencies.
- Parses lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) to analyze the full dependency tree.
- Compares declared and transitive dependencies against a list of known compromised packages.
- Inspects lifecycle hooks in all found `package.json` files for malicious commands.

**What it does *not* do:**
- ❌ Does **not** scan the `node_modules` directory

> ⚠️ Light mode relies on manifests and lockfiles only.  
> For full verification of installed dependencies, use `--deep`.

```bash
# Scan current directory
npx hulud-party-scanner

# Scan a specific project
npx hulud-party-scanner "path_to_local_project"
