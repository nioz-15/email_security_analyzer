"""
HTML Reporter for Email Security Analyzer.

This module generates professional HTML reports with integrated screenshots.
"""

import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from ..models.data_models import CompleteTestReport, TestSummary
from config.settings import settings

logger = logging.getLogger(__name__)


class HTMLReporter:
    """Professional HTML report generator."""

    def __init__(self):
        """Initialize the reporter."""
        self.output_dir = settings.REPORTS_DIR
        self.output_dir.mkdir(exist_ok=True)

    async def generate_professional_report(self, reports: List[CompleteTestReport]) -> Path:
        """Generate enhanced professional report with screenshots and better UI."""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary = TestSummary.from_reports(reports)

        # Copy screenshots to report directory for web access
        screenshots_web_dir = self.output_dir / "screenshots"
        screenshots_web_dir.mkdir(exist_ok=True)

        # Copy screenshots and get web paths
        await self._setup_screenshots(reports, screenshots_web_dir, timestamp)

        # Generate HTML report
        html_content = self._generate_html_content(reports, summary, timestamp)

        # Save the report
        html_path = self.output_dir / f"email_security_dashboard_{timestamp}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        # Log report details
        self._log_report_details(html_path, screenshots_web_dir)

        return html_path

    async def _setup_screenshots(self, reports: List[CompleteTestReport],
                                 screenshots_web_dir: Path, timestamp: str):
        """Copy screenshots and update paths for web access."""

        logger.info(f"Setting up screenshots directory: {screenshots_web_dir}")

        for i, report in enumerate(reports):
            logger.info(f"Processing screenshot for email {i + 1}: {report.failed_test.mail_subject[:30]}...")

            if report.mailbox_verification.screenshot_path:
                original_path = Path(report.mailbox_verification.screenshot_path)
                logger.info(f"   Original path: {original_path}")
                logger.info(f"   File exists: {original_path.exists()}")

                if original_path.exists():
                    # Create simple, predictable filename
                    screenshot_filename = f"email_{i + 1}_{report.failed_test.mail_type}_{timestamp}.png"
                    screenshot_dest = screenshots_web_dir / screenshot_filename

                    try:
                        # Copy screenshot
                        shutil.copy2(original_path, screenshot_dest)
                        logger.info(f"   Copied to: {screenshot_dest}")
                        logger.info(f"   Copy successful: {screenshot_dest.exists()}")

                        # Update path for HTML (relative to HTML file location)
                        report.mailbox_verification.screenshot_path = f"screenshots/{screenshot_filename}"
                        logger.info(f"   HTML relative path: {report.mailbox_verification.screenshot_path}")

                    except Exception as e:
                        logger.error(f"   Failed to copy screenshot: {e}")
                        report.mailbox_verification.screenshot_path = ""
                else:
                    logger.warning(f"   Original screenshot not found: {original_path}")
                    report.mailbox_verification.screenshot_path = ""
            else:
                logger.warning(f"   No screenshot path for email {i + 1}")
                report.mailbox_verification.screenshot_path = ""

    def _generate_html_content(self, reports: List[CompleteTestReport],
                               summary: TestSummary, timestamp: str) -> str:
        """Generate the complete HTML content."""

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Email Security Analysis Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="dashboard-container">
        {self._generate_header()}
        {self._generate_stats_grid(summary)}
        {self._generate_test_reports(reports)}
        {self._generate_footer(reports)}
    </div>
    {self._generate_modal()}
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>
        """
        return html_content

    def _generate_header(self) -> str:
        """Generate dashboard header."""
        return f"""
        <div class="dashboard-header">
            <h1 class="dashboard-title">
                <i class="fas fa-shield-alt"></i>
                Email Security Analysis Dashboard
            </h1>
            <p class="dashboard-subtitle">
                Comprehensive analysis and verification of email security test results
            </p>
            <div class="report-metadata">
                <div class="metadata-item">
                    <i class="fas fa-calendar"></i>
                    Generated: {datetime.now().strftime("%B %d, %Y at %H:%M")}
                </div>
                <div class="metadata-item">
                    <i class="fas fa-robot"></i>
                    AI-Powered Classification
                </div>
            </div>
        </div>
        """

    def _generate_stats_grid(self, summary: TestSummary) -> str:
        """Generate statistics grid."""
        return f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <div class="stat-icon">
                        <i class="fas fa-flask" style="color: var(--primary-color);"></i>
                    </div>
                    <div class="stat-number" style="color: var(--primary-color);">{summary.total_tests}</div>
                </div>
                <div class="stat-label">Total Tests</div>
                <div class="stat-change">
                    <i class="fas fa-chart-line"></i>
                    Comprehensive Analysis
                </div>
            </div>

            <div class="stat-card danger">
                <div class="stat-header">
                    <div class="stat-icon">
                        <i class="fas fa-exclamation-triangle" style="color: var(--danger-color);"></i>
                    </div>
                    <div class="stat-number" style="color: var(--danger-color);">{summary.real_issues}</div>
                </div>
                <div class="stat-label">Security Issues</div>
                <div class="stat-change">
                    <i class="fas fa-shield-alt"></i>
                    Critical Failures
                </div>
            </div>

            <div class="stat-card success">
                <div class="stat-header">
                    <div class="stat-icon">
                        <i class="fas fa-check-circle" style="color: var(--success-color);"></i>
                    </div>
                    <div class="stat-number" style="color: var(--success-color);">{summary.delay_issues}</div>
                </div>
                <div class="stat-label">Delay Issues</div>
                <div class="stat-change">
                    <i class="fas fa-clock"></i>
                    Security Working
                </div>
            </div>

            <div class="stat-card warning">
                <div class="stat-header">
                    <div class="stat-icon">
                        <i class="fas fa-tools" style="color: var(--warning-color);"></i>
                    </div>
                    <div class="stat-number" style="color: var(--warning-color);">{summary.code_issues}</div>
                </div>
                <div class="stat-label">Code Issues</div>
                <div class="stat-change">
                    <i class="fas fa-bug"></i>
                    Infrastructure
                </div>
            </div>

            <div class="stat-card security-score">
                <div class="stat-header">
                    <div class="stat-icon">
                        <i class="fas fa-award"></i>
                    </div>
                    <div class="score-circle">
                        {summary.security_success_rate:.0f}%
                    </div>
                </div>
                <div class="stat-label">Security Success Rate</div>
                <div class="stat-change">
                    <i class="fas fa-trophy"></i>
                    Overall Performance
                </div>
            </div>
        </div>
        """

    def _generate_test_reports(self, reports: List[CompleteTestReport]) -> str:
        """Generate individual test reports."""
        reports_html = '<div class="test-reports">'

        for i, report in enumerate(reports, 1):
            reports_html += self._generate_individual_test_report(report, i)

        reports_html += '</div>'
        return reports_html

    def _generate_individual_test_report(self, report: CompleteTestReport, index: int) -> str:
        """Generate an individual test report."""
        classification_class = report.final_classification.lower().replace('_', '-')

        icons = {
            'delay-issue': 'fas fa-clock',
            'real-issue': 'fas fa-exclamation-triangle',
            'code-issue': 'fas fa-tools'
        }

        # Generate status icons
        status_icons = self._generate_status_icons(report)

        return f"""
        <div class="test-card">
            <div class="test-header {classification_class}">
                <div class="test-title-row">
                    <div class="test-title">
                        <i class="{icons.get(classification_class, 'fas fa-question')}"></i>
                        Email {index}: {report.failed_test.mail_type.upper()} - {report.failed_test.mail_subject[:50]}...
                    </div>
                    <div class="test-badge {classification_class}">
                        {report.final_classification.replace('_', ' ')}
                    </div>
                </div>
                {f'<div style="margin-top: 0.5rem;">{" ".join(status_icons)}</div>' if status_icons else ''}
            </div>

            <div class="test-content">
                {self._generate_test_configuration_section(report)}
                {self._generate_verification_results_section(report)}
                {self._generate_screenshot_section(report)}
                {self._generate_ai_analysis_section(report)}
            </div>
        </div>
        """

    def _generate_status_icons(self, report: CompleteTestReport) -> List[str]:
        """Generate status icons for a test report."""
        status_icons = []

        if report.mailbox_verification.quarantined_subject_found:
            status_icons.append(
                '<span class="status-icon warning"><i class="fas fa-shield-alt"></i> Quarantined</span>'
            )
        if report.mailbox_verification.phishing_alert_found:
            status_icons.append(
                '<span class="status-icon warning"><i class="fas fa-exclamation-triangle"></i> Phishing Alert</span>'
            )
        if report.mailbox_verification.original_subject_found and report.failed_test.mail_type == 'clean':
            status_icons.append(
                '<span class="status-icon success"><i class="fas fa-check-circle"></i> Normal Delivery</span>'
            )
        if report.mailbox_verification.action_applied:
            status_icons.append(
                '<span class="status-icon success"><i class="fas fa-check"></i> Security Applied</span>'
            )

        return status_icons

    def _generate_test_configuration_section(self, report: CompleteTestReport) -> str:
        """Generate test configuration section."""
        return f"""
        <div class="content-section">
            <div class="section-title">
                <i class="fas fa-cog section-icon"></i>
                Test Configuration
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Mail Type</div>
                    <div class="detail-value">
                        <i class="fas fa-tag"></i> {report.failed_test.mail_type.upper()}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Subject</div>
                    <div class="detail-value">{report.failed_test.mail_subject}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Email Address</div>
                    <div class="detail-value">{report.failed_test.mail_address}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Expected Behavior</div>
                    <div class="detail-value">{report.failed_test.expected_behavior}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Test Duration</div>
                    <div class="detail-value">
                        <i class="fas fa-stopwatch"></i> {report.failed_test.test_duration:.1f} seconds
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Test Context</div>
                    <div class="detail-value">{report.failed_test.test_name}</div>
                </div>
            </div>
        </div>
        """

    def _generate_verification_results_section(self, report: CompleteTestReport) -> str:
        """Generate verification results section."""
        return f"""
        <div class="content-section">
            <div class="section-title">
                <i class="fas fa-search section-icon"></i>
                Verification Results
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Mail Found</div>
                    <div class="detail-value">
                        {'<span class="status-icon success"><i class="fas fa-check"></i> Yes</span>' if report.mailbox_verification.mail_found else '<span class="status-icon danger"><i class="fas fa-times"></i> No</span>'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Original Subject Found</div>
                    <div class="detail-value">
                        {'<span class="status-icon success"><i class="fas fa-check"></i> Yes</span>' if report.mailbox_verification.original_subject_found else '<span class="status-icon danger"><i class="fas fa-times"></i> No</span>'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Quarantined Version</div>
                    <div class="detail-value">
                        {'<span class="status-icon warning"><i class="fas fa-shield-alt"></i> Yes</span>' if report.mailbox_verification.quarantined_subject_found else '<span class="status-icon"><i class="fas fa-times"></i> No</span>'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Phishing Alert</div>
                    <div class="detail-value">
                        {'<span class="status-icon warning"><i class="fas fa-exclamation-triangle"></i> Yes</span>' if report.mailbox_verification.phishing_alert_found else '<span class="status-icon"><i class="fas fa-times"></i> No</span>'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Expected Action</div>
                    <div class="detail-value">{report.mailbox_verification.expected_action}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Actual Action</div>
                    <div class="detail-value">{report.mailbox_verification.actual_action}</div>
                </div>
            </div>
        </div>
        """

    def _generate_screenshot_section(self, report: CompleteTestReport) -> str:
        """Generate screenshot section."""
        screenshot_section = f"""
        <div class="content-section">
            <div class="section-title">
                <i class="fas fa-camera section-icon"></i>
                Mailbox Verification Screenshot
            </div>
            <div class="screenshot-section">
        """

        # Screenshot section with proper error handling
        if report.mailbox_verification.screenshot_path:
            screenshot_full_path = self.output_dir / report.mailbox_verification.screenshot_path
            if screenshot_full_path.exists():
                screenshot_section += f"""
                <div class="screenshot-container">
                    <img src="{report.mailbox_verification.screenshot_path}" 
                         alt="Email verification for {report.failed_test.mail_type}: {report.failed_test.mail_subject[:30]}..."
                         class="screenshot-image"
                         onclick="openModal(this.src)"
                         title="Click to view full size - {report.failed_test.mail_type.upper()} email verification"
                         onload="console.log('Screenshot loaded: {report.mailbox_verification.screenshot_path}')"
                         onerror="console.error('Screenshot failed: {report.mailbox_verification.screenshot_path}'); this.style.display='none'; this.nextElementSibling.style.display='block';">
                    <div class="screenshot-error" style="display: none;">
                        <i class="fas fa-exclamation-triangle" style="color: #ef4444; font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <p>Screenshot failed to load</p>
                        <p style="font-size: 0.8rem; margin-top: 0.5rem;">Path: {report.mailbox_verification.screenshot_path}</p>
                    </div>
                    <p style="margin-top: 0.5rem; color: var(--text-secondary); font-size: 0.9rem;">
                        <i class="fas fa-info-circle"></i> 
                        {report.failed_test.mail_type.upper()} email verification - Click to view full size
                    </p>
                </div>
                """
            else:
                screenshot_section += f"""
                <div class="screenshot-error">
                    <i class="fas fa-exclamation-triangle" style="color: #ef4444; font-size: 2rem; margin-bottom: 0.5rem;"></i>
                    <p>Screenshot file not found</p>
                    <p style="font-size: 0.8rem; margin-top: 0.5rem;">Expected: {screenshot_full_path}</p>
                </div>
                """
        else:
            screenshot_section += f"""
            <div class="no-screenshot">
                <i class="fas fa-image" style="font-size: 2rem; opacity: 0.3; margin-bottom: 0.5rem;"></i>
                <p>No screenshot available for this verification</p>
            </div>
            """

        screenshot_section += """
            </div>
        </div>
        """
        return screenshot_section

    def _generate_ai_analysis_section(self, report: CompleteTestReport) -> str:
        """Generate AI analysis section."""
        return f"""
        <div class="ai-analysis">
            <div class="ai-header">
                <i class="fas fa-robot"></i>
                AI Analysis & Classification
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Classification</div>
                    <div class="detail-value">
                        <strong>{report.ai_analysis.classification.replace('_', ' ')}</strong>
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Confidence Level</div>
                    <div class="detail-value">
                        <div class="confidence-display">
                            <div class="confidence-bar">
                                <div class="confidence-fill" style="width: {report.ai_analysis.confidence}%"></div>
                            </div>
                            <div class="confidence-percentage">{report.ai_analysis.confidence}%</div>
                        </div>
                    </div>
                </div>
            </div>
            <div style="margin-top: 1rem;">
                <div class="detail-label">
                    <i class="fas fa-lightbulb"></i> Analysis Explanation
                </div>
                <div class="detail-value" style="margin-top: 0.5rem; line-height: 1.6;">
                    {report.ai_analysis.explanation}
                </div>
            </div>
            <div style="margin-top: 1rem;">
                <div class="detail-label">
                    <i class="fas fa-tasks"></i> Recommended Action
                </div>
                <div class="detail-value" style="margin-top: 0.5rem; line-height: 1.6;">
                    {report.ai_analysis.recommended_action}
                </div>
            </div>
        </div>
        """

    def _generate_footer(self, reports: List[CompleteTestReport]) -> str:
        """Generate footer with debug information."""
        screenshots_web_dir = self.output_dir / "screenshots"

        return f"""
        <div class="dashboard-footer">
            <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">
                <i class="fas fa-chart-line"></i>
                <strong>Email Security Analysis Complete</strong>
            </p>
            <p>
                Report generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")} | 
                <i class="fas fa-shield-alt"></i> Email Security Test Analysis System |
                <i class="fas fa-robot"></i> AI-Powered Classification
            </p>
            <div class="debug-info">
                <strong>Debug Information:</strong><br>
                Report Directory: {self.output_dir}<br>
                Screenshots Directory: {screenshots_web_dir}<br>
                Screenshots Available: {sum(1 for r in reports if r.mailbox_verification.screenshot_path)}/{len(reports)}<br>
                Screenshot Files: {len(list(screenshots_web_dir.glob('*.png'))) if screenshots_web_dir.exists() else 0}
            </div>
        </div>
        """

    def _generate_modal(self) -> str:
        """Generate modal for screenshot viewing."""
        return """
        <div id="screenshotModal" class="modal" onclick="closeModal()">
            <span class="close" onclick="closeModal()">&times;</span>
            <img class="modal-content" id="modalImage">
        </div>
        """

    def _get_css_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        :root {
            --primary-color: #2563eb;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --secondary-color: #6b7280;
            --background-color: #f8fafc;
            --card-background: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px 0;
        }

        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .dashboard-header {
            background: var(--card-background);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-xl);
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .dashboard-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--success-color), var(--warning-color));
        }

        .dashboard-title {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
        }

        .dashboard-subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .report-metadata {
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
            margin-top: 1.5rem;
        }

        .metadata-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--background-color);
            border-radius: 8px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--card-background);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow-md);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--primary-color);
        }

        .stat-card.success::before { background: var(--success-color); }
        .stat-card.warning::before { background: var(--warning-color); }
        .stat-card.danger::before { background: var(--danger-color); }

        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .stat-icon {
            font-size: 2rem;
            opacity: 0.8;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
        }

        .stat-label {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-change {
            margin-top: 0.5rem;
            font-size: 0.8rem;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .security-score {
            background: linear-gradient(135deg, var(--success-color), #059669);
            color: white;
            text-align: center;
        }

        .security-score::before {
            background: rgba(255,255,255,0.2);
        }

        .score-circle {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: rgba(255,255,255,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 1rem auto;
            font-size: 1.5rem;
            font-weight: 700;
        }

        .test-reports {
            display: grid;
            gap: 1.5rem;
        }

        .test-card {
            background: var(--card-background);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow-md);
            transition: all 0.3s ease;
        }

        .test-card:hover {
            box-shadow: var(--shadow-xl);
        }

        .test-header {
            padding: 1.5rem;
            border-left: 4px solid;
            position: relative;
        }

        .test-header.delay-issue {
            border-left-color: var(--success-color);
            background: linear-gradient(135deg, #ecfdf5 0%, #f0fdf4 100%);
        }

        .test-header.real-issue {
            border-left-color: var(--danger-color);
            background: linear-gradient(135deg, #fef2f2 0%, #fef5f5 100%);
        }

        .test-header.code-issue {
            border-left-color: var(--warning-color);
            background: linear-gradient(135deg, #fffbeb 0%, #fefce8 100%);
        }

        .test-title-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .test-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .test-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .test-badge.delay-issue {
            background: var(--success-color);
            color: white;
        }

        .test-badge.real-issue {
            background: var(--danger-color);
            color: white;
        }

        .test-badge.code-issue {
            background: var(--warning-color);
            color: var(--text-primary);
        }

        .test-content {
            padding: 0 1.5rem 1.5rem;
        }

        .content-section {
            margin-bottom: 2rem;
        }

        .section-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .section-icon {
            color: var(--primary-color);
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .detail-item {
            background: var(--background-color);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            transition: all 0.2s ease;
        }

        .detail-item:hover {
            background: #f1f5f9;
            border-color: var(--primary-color);
        }

        .detail-label {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .detail-value {
            color: var(--text-secondary);
            font-weight: 500;
        }

        .screenshot-section {
            background: var(--background-color);
            border-radius: 8px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
        }

        .screenshot-container {
            text-align: center;
            margin-top: 1rem;
        }

        .screenshot-image {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: var(--shadow-md);
            cursor: pointer;
            transition: transform 0.2s ease;
        }

        .screenshot-image:hover {
            transform: scale(1.02);
        }

        .screenshot-error {
            color: var(--text-secondary);
            font-style: italic;
            text-align: center;
            padding: 2rem;
            background: #fef2f2;
            border-radius: 8px;
            border: 2px dashed #fca5a5;
        }

        .no-screenshot {
            color: var(--text-secondary);
            font-style: italic;
            text-align: center;
            padding: 2rem;
            background: #f8fafc;
            border-radius: 8px;
            border: 2px dashed var(--border-color);
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
            cursor: pointer;
        }

        .modal-content {
            margin: auto;
            display: block;
            width: 90%;
            max-width: 1200px;
            margin-top: 2%;
            cursor: default;
        }

        .close {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }

        .close:hover {
            color: #bbb;
        }

        .ai-analysis {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 1px solid #0ea5e9;
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
        }

        .ai-analysis::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #0ea5e9, #3b82f6);
        }

        .ai-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .confidence-display {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin: 1rem 0;
        }

        .confidence-bar {
            flex: 1;
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--success-color) 0%, #3b82f6 50%, #6366f1 100%);
            transition: width 0.5s ease;
            border-radius: 4px;
        }

        .confidence-percentage {
            font-weight: 600;
            color: var(--text-primary);
            min-width: 50px;
        }

        .status-icon {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            font-weight: 500;
        }

        .status-icon.success { color: var(--success-color); }
        .status-icon.danger { color: var(--danger-color); }
        .status-icon.warning { color: var(--warning-color); }

        .dashboard-footer {
            background: var(--card-background);
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            margin-top: 2rem;
            box-shadow: var(--shadow-md);
            color: var(--text-secondary);
        }

        .debug-info {
            margin-top: 1rem;
            padding: 1rem;
            background: #f0f0f0;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.8rem;
            text-align: left;
        }

        @media (max-width: 768px) {
            .dashboard-container {
                padding: 0 10px;
            }

            .dashboard-title {
                font-size: 2rem;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

            .test-title-row {
                flex-direction: column;
                align-items: stretch;
            }

            .modal-content {
                width: 95%;
                margin-top: 10%;
            }
        }

        @media print {
            body {
                background: white;
            }

            .modal {
                display: none !important;
            }

            .test-card {
                break-inside: avoid;
                margin-bottom: 1rem;
            }
        }
        """

    def _get_javascript(self) -> str:
        """Get JavaScript for the report."""
        return """
        function openModal(src) {
            console.log('Opening modal for:', src);
            document.getElementById('screenshotModal').style.display = 'block';
            document.getElementById('modalImage').src = src;
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('screenshotModal').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
            }
        });

        window.addEventListener('load', function() {
            const confidenceBars = document.querySelectorAll('.confidence-fill');
            confidenceBars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = width;
                }, 500);
            });
        });
        """

    def _log_report_details(self, html_path: Path, screenshots_web_dir: Path):
        """Log comprehensive report details."""
        logger.info(f"Enhanced Dashboard saved: {html_path}")
        logger.info(f"Screenshots directory: {screenshots_web_dir}")
        logger.info(f"Screenshot files in directory:")

        if screenshots_web_dir.exists():
            for screenshot_file in screenshots_web_dir.glob("*.png"):
                logger.info(f"   {screenshot_file.name} ({screenshot_file.stat().st_size:,} bytes)")

        logger.info(f"Report structure:")
        logger.info(f"   HTML file: {html_path.exists()}")
        logger.info(f"   Screenshots dir: {screenshots_web_dir.exists()}")
        logger.info(
            f"   Total screenshots: {len(list(screenshots_web_dir.glob('*.png'))) if screenshots_web_dir.exists() else 0}"
        )