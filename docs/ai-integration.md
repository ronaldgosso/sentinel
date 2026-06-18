# AI Integration with Mistral

Sentinel uses **Mistral** to enrich findings with:
- Risk re-evaluation (severity)
- Attack scenario explanation
- Specific hardening suggestions
- Priority (Immediate/Next Sprint/Backlog)

## Requirements

- A Mistral API key (free tier available at [Mistral AI](https://mistral.ai))
- Internet access (for cloud backend)

## Set the API Key

You can set the key via:
- Environment variable: `export MISTRAL_API_KEY=your-key`
- CLI flag: `--ai-api-key your-key`
- `.sentinel.yml` (not recommended for security)

## Backend Options

- `--ai-backend cloud` - uses the Mistral API (default)
- `--ai-backend local` - uses Ollama (requires local installation)

## Privacy

When using the cloud backend, code snippets are sent to Mistral. We do not store any data. For privacy-sensitive projects, use the local backend with Ollama.
