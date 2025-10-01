# hulud-party-scanner

Project integrity scanner for known vulnerabilities and suspicious patterns related to the Shai-Hulud supply-chain attack.

This project is a Node.js implementation based on the original shell script from [sngular/shai-hulud-integrity-scanner](https://github.com/sngular/shai-hulud-integrity-scanner).

## Usage

To scan a project, run the following command in your terminal. You can target a specific directory or run it in your current directory.

```bash
npx hulud-party-scanner "/path/to/your/project"
```

Si no se especifica una ruta, el escáner se ejecutará en el directorio actual.