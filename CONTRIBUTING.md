# Contributing to CursorMover

Thank you for considering contributing to CursorMover! We welcome contributions from everyone.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub with:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Your environment (OS, Python version, Cursor version)
- Any relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please open an issue with:

- A clear description of the feature
- Why it would be useful
- How it might work

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure everything works (`python -m unittest discover -s tests -v`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow the Google Python Style Guide
- Use Google Style Docstrings
- Use Better Comments style for inline comments (symbols: `*`, `!`, `?`, `TODO:`)
- All comments and docstrings must be in English
- Ensure your code passes all existing tests

### Testing

Before submitting a PR, make sure all tests pass:

```bash
python -m unittest discover -s tests -v
```

If you add new functionality, please include appropriate tests.

## Development Setup

1. Clone the repository
2. Run `./run.ps1` (Windows) or `./run.sh` (Linux/macOS) to set up the virtual environment
3. Make your changes
4. Test your changes

## Questions?

Feel free to open an issue for any questions or clarifications.

Thank you for your contributions!
