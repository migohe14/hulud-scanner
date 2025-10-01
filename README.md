# hulud-party-scanner

Project integrity scanner for known vulnerabilities and suspicious patterns related to the Shai-Hulud supply-chain attack.

This project is a Node.js implementation based on the original shell script from [sngular/shai-hulud-integrity-scanner](https://github.com/sngular/shai-hulud-integrity-scanner).

## Usage

You can run the scanner against your current project directory, or specify a path to another one.

To scan the current directory:

```bash
npx hulud-party-scanner
```

To scan a specific directory:
```bash
npx hulud-party-scanner "/path/to/your/project"
```
