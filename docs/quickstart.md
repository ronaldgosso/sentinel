# Quickstart

1. **Install Sentinel**  
   ```bash
   pip install sentinel-security
   ```

2. **Run a basic scan**  
   ```bash
   sentinel scan .
   ```
   This runs SAST and SCA on the current directory.

3. **Enable AI**  
   Get a free Mistral API key from [Mistral AI](https://mistral.ai).  
   ```bash
   export MISTRAL_API_KEY=your-key
   sentinel scan . --ai
   ```

4. **Apply auto-fix**  
   ```bash
   sentinel scan . --fix
   ```
   You\'ll be prompted to apply fixes for each finding.

5. **Generate a report**  
   ```bash
   sentinel scan . --output-format html --output-file report.html
   ```

6. **Integrate into CI**  
   See the [CI/CD guide](ci-cd.md).
