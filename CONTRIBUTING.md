# Contributing to Sentinel

We love contributions! Here\'s how you can help.

## Reporting Issues

- Use the [issue tracker](https://github.com/ronaldgosso/sentinel/issues).
- Provide a minimal reproducible example.

## Suggesting Features

- Open a feature request issue.
- Explain the use case and expected behaviour.

## Adding a New Detector

1. Create a new Python file in `src/sentinel/scanners/sast/detectors/`.
2. Implement a function that takes `(ast.AST, source, filename)` and returns a list of dicts.
3. Add your function to `DETECTOR_MAP` in `src/sentinel/scanners/sast/engine.py`.
4. Add a corresponding YAML rule in `rules/`.

## Pull Request Process

1. Fork the repo and create a branch.
2. Run `pre-commit install`.
3. Write tests for your changes.
4. Update documentation if needed.
5. Submit a PR against the `main` branch.

## Code Style

- Follow PEP 8 (enforced by Ruff).
- Add type hints.
- Keep code coverage above 80%.

Thank you!
