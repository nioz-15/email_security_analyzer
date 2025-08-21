# Email Security Analyzer 📧🔒

> AI-powered analysis of email security test failures with professional reporting

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Overview

Email Security Analyzer is a comprehensive tool that analyzes email security test failures from Allure reports and provides intelligent classification using AI. It generates professional HTML reports with integrated screenshots and actionable insights.

### Key Features

- 🤖 **AI-Powered Classification**: Uses OpenAI to intelligently classify failures
- 📊 **Professional Reports**: Generates beautiful HTML dashboards with interactive charts
- 📸 **Screenshot Integration**: Click-to-expand screenshot modals for visual verification
- 🔍 **Smart Parsing**: Extracts only real failures (AssertionError) from Allure reports
- 📧 **Email Deduplication**: Prevents processing duplicate emails across test runs
- 🎯 **Accurate Detection**: Distinguishes between security issues, delays, and code problems
- 📱 **Mobile Responsive**: Works perfectly on desktop, tablet, and mobile devices

## Architecture

```
email_security_analyzer/
├── src/
│   ├── models/          # Data models and structures
│   ├── parsers/         # Allure report parsing
│   ├── verifiers/       # Email verification via Playwright
│   ├── analyzers/       # AI-powered analysis
│   ├── reporters/       # HTML report generation
│   ├── core/           # Main orchestration logic
│   └── utils/          # Helper utilities
├── config/             # Configuration management
├── tests/              # Unit and integration tests
└── output/             # Generated reports and screenshots
```

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenAI API key
- Email account credentials for verification

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourorg/email-security-analyzer.git
   cd email-security-analyzer
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Playwright browsers**
   ```bash
   playwright install chromium
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

5. **Run the analyzer**
   ```bash
   python main.py --reports /path/to/allure-reports
   ```

### Alternative Installation

Install as a package:
```bash
pip install -e .
email-security-analyzer --reports /path/to/allure-reports
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Required
OPENAI_API_KEY=sk-your-openai-api-key
MAILBOX_PASSWORD=your-email-password

# Optional
WEBMAIL_URL=https://outlook.office.com
BROWSER_HEADLESS=false
BROWSER_TIMEOUT=30000
AI_MODEL=gpt-4o
AI_TEMPERATURE=0.1
```

### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | Required |
| `MAILBOX_PASSWORD` | Email password for verification | Required |
| `WEBMAIL_URL` | Webmail interface URL | `https://outlook.office.com` |
| `BROWSER_HEADLESS` | Run browser in headless mode | `false` |
| `BROWSER_TIMEOUT` | Browser operation timeout (ms) | `30000` |
| `AI_MODEL` | OpenAI model to use | `gpt-4o` |
| `AI_TEMPERATURE` | AI response randomness | `0.1` |

## Usage

### Basic Usage

```bash
python main.py --reports /path/to/allure-reports
```

### Advanced Usage

```bash
python main.py \
  --reports /path/to/allure-reports \
  --password your-password \
  --api-key sk-your-key \
  --output /custom/output \
  --log-level DEBUG \
  --no-browser
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--reports`, `-r` | Path to Allure reports folder (required) |
| `--password`, `-p` | Mailbox password |
| `--api-key`, `-k` | OpenAI API key |
| `--output`, `-o` | Custom output directory |
| `--log-level`, `-l` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `--log-file` | Custom log file path |
| `--no-browser` | Run in headless mode |
| `--timeout` | Browser timeout in seconds |
| `--version`, `-v` | Show version and exit |

## How It Works

### 1. Report Parsing
- Scans Allure HTML reports for AssertionError failures
- Extracts email subjects, recipients, and test context
- Deduplicates based on email content (not test names)

### 2. Email Verification
- Uses Playwright to log into webmail
- Searches for emails in various forms:
  - Original subject (for clean emails)
  - "Quarantined [subject]" (for malware/EICAR)
  - "Phishing Alert! [subject]" (for phishing)
- Captures screenshots for evidence

### 3. AI Classification
- Analyzes verification results with OpenAI
- Classifies failures into three categories:
  - **REAL_ISSUE**: Security system failed
  - **DELAY_ISSUE**: Security worked, just slow
  - **CODE_ISSUE**: Technical/infrastructure problem

### 4. Report Generation
- Creates professional HTML dashboard
- Includes interactive charts and statistics
- Embeds screenshots with click-to-expand
- Mobile-responsive design

## Classification Logic

### DELAY_ISSUE ✅
Security system worked correctly, just slow delivery:
- Clean email delivered normally
- Phishing email has "Phishing Alert!" prefix
- Malware/EICAR quarantined properly

### REAL_ISSUE ❌
Security system failed to protect users:
- Phishing email without warning
- Malware delivered without quarantine
- Clean email incorrectly blocked

### CODE_ISSUE 🔧
Technical/infrastructure problems:
- Browser login failures
- Network connectivity issues
- Test framework bugs

## Sample Output

```
📧 Email Security Analyzer - Professional Edition
===============================================

🔍 Parsing Allure reports from: /path/to/reports
📧 Extracting unique email failures...

📊 ANALYSIS COMPLETE!
===============================================
📈 Results Summary:
   📧 Total Unique Emails: 15
   🚨 Security Issues (Critical): 2
   ⏰ Delay Issues (Security Working): 11
   🔧 Code Issues (Infrastructure): 2
   🛡️  Security Success Rate: 84.6%

📋 Detailed Email Analysis:
   1. ⏰ PHISHING: DELAY ISSUE ⚠️ PHISHING_ALERT 📸
      📝 Subject: Test phishing email with malicious link...
   2. 🚨 MALWARE: REAL ISSUE 📸
      📝 Subject: EICAR test file attachment...

🎉 Professional Dashboard Generated!
📁 Report Location: /output/reports/email_security_dashboard_20241201_143022.html
```

## API Reference

### Core Classes

#### `CompleteMailVerifier`
Main orchestrator class that coordinates the analysis process.

```python
from src.core.mail_verifier import CompleteMailVerifier

verifier = CompleteMailVerifier(
    reports_folder="/path/to/reports",
    password="email-password",
    openai_api_key="sk-..."
)

reports = await verifier.run_complete_analysis()
```

#### `AllureParser`
Parses Allure HTML reports and extracts failed tests.

```python
from src.parsers.allure_parser import AllureParser

parser = AllureParser("/path/to/reports")
failed_tests = parser.extract_failed_mail_tests()
```

#### `PlaywrightMailboxVerifier`
Verifies email delivery using browser automation.

```python
from src.verifiers.mailbox_verifier import PlaywrightMailboxVerifier

verifier = PlaywrightMailboxVerifier("password")
result = await verifier.verify_mail_delivery(failed_test)
```

#### `AIAnalyzer`
Analyzes test failures using AI classification.

```python
from src.analyzers.ai_analyzer import AIAnalyzer

analyzer = AIAnalyzer("sk-openai-key")
analysis = analyzer.analyze_test_failure(failed_test, verification_result)
```

### Data Models

All data models are defined in `src/models/data_models.py`:
- `FailedTest`: Represents a failed email test
- `MailVerificationResult`: Email verification outcome
- `AIAnalysisResult`: AI classification result
- `CompleteTestReport`: Complete analysis report

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_parsers.py

# Run with verbose output
pytest -v
```

### Test Structure

```
tests/
├── test_parsers.py       # Test Allure parsing
├── test_verifiers.py     # Test email verification
├── test_analyzers.py     # Test AI analysis
├── test_reporters.py     # Test report generation
└── fixtures/             # Test data and fixtures
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run code formatting
black src/
flake8 src/

# Type checking
mypy src/
```

### Code Style

This project uses:
- **Black** for code formatting
- **Flake8** for linting
- **MyPy** for type checking
- **Pytest** for testing

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Troubleshooting

### Common Issues

#### "No HTML files found"
- Ensure Allure reports folder contains `.html` files
- Check folder path is correct

#### "OpenAI API key not set"
- Set `OPENAI_API_KEY` environment variable
- Or use `--api-key` command line option

#### "Browser login failed"
- Verify email credentials are correct
- Check if 2FA is enabled (may need app password)
- Ensure webmail URL is accessible

#### "Screenshots not displaying"
- Check screenshot files exist in output folder
- Verify browser permissions for file access
- Try different browser if images don't load

### Debug Mode

Run with debug logging for detailed information:

```bash
python main.py --reports /path/to/reports --log-level DEBUG
```

### Performance Tips

- Use `--no-browser` for faster headless operation
- Increase `--timeout` for slow email systems
- Process smaller batches of reports for memory efficiency

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📚 [Documentation](https://github.com/yourorg/email-security-analyzer/wiki)
- 🐛 [Bug Reports](https://github.com/yourorg/email-security-analyzer/issues)
- 💬 [Discussions](https://github.com/yourorg/email-security-analyzer/discussions)

## Acknowledgments

- [OpenAI](https://openai.com/) for AI analysis capabilities
- [Playwright](https://playwright.dev/) for browser automation
- [Allure](https://docs.qameta.io/allure/) for test reporting format

---

**Email Security Analyzer** - Making email security testing intelligent and actionable! 🚀