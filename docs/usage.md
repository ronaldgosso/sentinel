# Usage

## Commands

### `scan`
Scan a Python project.

```bash
sentinel scan [OPTIONS] [PATH]
```

Options:
- `--ai` / `--no-ai` - enable/disable AI (default: on)
- `--ai-backend [local|cloud]` - AI backend (default: cloud)
- `--ai-api-key TEXT` - Mistral API key
- `--ci` - non-interactive mode, exit with code
- `--skip-sast` - skip SAST scanning
- `--skip-sca` - skip SCA scanning
- `--dast URL` - enable DAST against the given URL
- `--fix` - apply auto-fixes interactively
- `--output-format [json|sarif|html]` - export format
- `--output-file PATH` - output file
- `--fail-on [critical|high|medium|low]` - fail CI threshold (default: high)

### `init`
Create a default `.sentinel.yml` configuration file.

```bash
sentinel init
```

### `update-db`
Refresh the vulnerability cache.

```bash
sentinel update-db [--force]
```

## Configuration File

Place a `.sentinel.yml` in your project root or home directory.  
Example:

```yaml
exclude_patterns:
  - .venv
  - tests
severity_threshold: medium
ai_enabled: true
ai_backend: cloud
max_workers: 4
```
