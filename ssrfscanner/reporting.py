"""Report generation (TXT/CSV/JSON/HTML) for scan results."""

import asyncio
import csv
import json
import threading
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from typing import Any, Dict, List

from .models import ScanResult


class Reporter:
    def __init__(self, output_dir: str, output_format: str = 'all'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        self.output_format = output_format
        self.txt_output = self.output_dir / 'report.txt'
        self.json_output = self.output_dir / 'report.json'
        self.csv_output = self.output_dir / 'report.csv'
        self.html_output = self.output_dir / 'report.html'
        # Serializes disk writes when they run in worker threads.
        self._write_lock = threading.Lock()

    def add_result(self, result: ScanResult):
        """Add a scan result and write it synchronously (blocking).

        Kept for non-async callers. Async callers should prefer
        ``add_result_async`` so the disk write does not block the event loop.
        """
        self.results.append(result)
        with self._write_lock:
            self._write_result(result)

    async def add_result_async(self, result: ScanResult):
        """Append in-memory (fast, on the loop) and offload the file write.

        The blocking TXT/CSV/JSON writes are run in a worker thread via
        ``asyncio.to_thread`` so they never stall the scanner's event loop.
        """
        self.results.append(result)
        await asyncio.to_thread(self._write_result_locked, result)

    def _write_result_locked(self, result: ScanResult):
        """Thread-safe wrapper around _write_result for offloaded writes."""
        with self._write_lock:
            self._write_result(result)

    def _write_result(self, result: ScanResult):
        """Write result to configured output formats in real-time"""
        formats = self.output_format.lower().split(',') if ',' in self.output_format else [self.output_format.lower()]
        
        if 'all' in formats or 'txt' in formats:
            self._write_txt(result)
        
        if 'all' in formats or 'csv' in formats:
            self._write_csv(result)
        
        if 'all' in formats or 'json' in formats:
            self._write_json(result)
    
    def _write_txt(self, result: ScanResult):
        """Write to TXT format"""
        with open(self.txt_output, 'a') as f:
            f.write(f"\nPotential SSRF Found!\n")
            f.write(f"URL: {result.url}\n")
            f.write(f"Attack Type: {result.attack_type}\n")
            f.write(f"Payload: {result.payload}\n")
            f.write(f"Response Code: {result.response_code}\n")
            f.write(f"Response Size: {result.response_size}\n")
            f.write(f"Verification Method: {result.verification_method}\n")
            f.write(f"Notes: {result.notes}\n")
            f.write("-" * 50 + "\n")
    
    def _write_csv(self, result: ScanResult):
        """Write to CSV format"""
        with open(self.csv_output, 'a', newline='') as f:
            writer = csv.writer(f)
            if f.tell() == 0:  # Write header if file is empty
                writer.writerow([
                    'URL', 'Attack Type', 'Payload', 'Response Code',
                    'Response Size', 'Verification Method', 'Timestamp', 'Notes'
                ])
            writer.writerow([
                result.url, result.attack_type, result.payload,
                result.response_code, result.response_size,
                result.verification_method, result.timestamp, result.notes
            ])
    
    @staticmethod
    def _result_to_dict(result: ScanResult) -> Dict[str, Any]:
        """Serialize a ScanResult to a JSON-friendly dict."""
        return {
            'url': result.url,
            'attack_type': result.attack_type,
            'payload': result.payload,
            'response_code': result.response_code,
            'response_size': result.response_size,
            'verification_method': result.verification_method,
            'timestamp': result.timestamp.isoformat(),
            'notes': result.notes
        }

    def _write_json(self, result: ScanResult):
        """Write to JSON format.

        Serializes the full in-memory results list rather than reading the
        existing file back on every finding. This removes the per-result disk
        read (and the fragile JSONDecodeError recovery) that previously turned
        report writing into an O(n^2) read-modify-write cycle.
        """
        # Snapshot the list first: this may run in a worker thread, so avoid
        # iterating while the event loop could be appending.
        results_json = [self._result_to_dict(r) for r in list(self.results)]

        with open(self.json_output, 'w') as f:
            json.dump(results_json, f, indent=2)

    def generate_summary(self) -> str:
        """Generate final summary report"""
        stats = self._calculate_statistics()
        
        summary = "\n" + "="*50 + "\n"
        summary += "SSRF Scan Summary\n"
        summary += "="*50 + "\n\n"
        
        # Add statistics
        summary += "Statistics:\n"
        summary += "-"*20 + "\n"
        for key, value in stats.items():
            summary += f"{key}: {value}\n"
        
        # Add vulnerability breakdown
        summary += "\nVulnerabilities by Attack Type:\n"
        summary += "-"*30 + "\n"
        grouped = self._group_vulnerabilities()
        for attack_type, results in grouped.items():
            summary += f"{attack_type}: {len(results)} found\n"
        
        summary += "\n" + "="*50 + "\n"
        summary += f"Detailed results saved in:\n"
        
        formats = self.output_format.lower().split(',') if ',' in self.output_format else [self.output_format.lower()]
        if 'all' in formats or 'txt' in formats:
            summary += f"Text Report: {self.txt_output}\n"
        if 'all' in formats or 'csv' in formats:
            summary += f"CSV Report: {self.csv_output}\n"
        if 'all' in formats or 'json' in formats:
            summary += f"JSON Report: {self.json_output}\n"
        if 'all' in formats or 'html' in formats:
            summary += f"HTML Report: {self.html_output}\n"
        
        # Write summary to file
        with open(self.output_dir / 'summary.txt', 'w') as f:
            f.write(summary)
        
        # Generate HTML report if requested
        if 'all' in formats or 'html' in formats:
            self._generate_html_report(stats, grouped)
        
        return summary
    
    def _generate_html_report(self, stats: Dict, grouped: Dict):
        """Generate HTML report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>SSRF Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
        .stat-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
        .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .vuln-high { color: #e74c3c; font-weight: bold; }
        .vuln-medium { color: #f39c12; }
        .vuln-low { color: #27ae60; }
        .attack-type { display: inline-block; padding: 4px 8px; background: #3498db; color: white; border-radius: 3px; font-size: 12px; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
        .payload { font-family: monospace; background: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SSRF Scanner Report</h1>
        <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <h2>📊 Statistics</h2>
        <div class="stats">
"""
        
        for key, value in stats.items():
            html += f"""
            <div class="stat-card">
                <div class="stat-label">{key}</div>
                <div class="stat-value">{value}</div>
            </div>
"""
        
        html += """
        </div>
        
        <h2>🎯 Vulnerabilities by Attack Type</h2>
        <table>
            <tr>
                <th>Attack Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""
        
        total_vulns = sum(len(results) for results in grouped.values())
        for attack_type, results in grouped.items():
            percentage = (len(results) / total_vulns * 100) if total_vulns > 0 else 0
            html += f"""
            <tr>
                <td><span class="attack-type">{html_escape(str(attack_type))}</span></td>
                <td>{len(results)}</td>
                <td>{percentage:.1f}%</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>🚨 Detailed Findings</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Attack Type</th>
                <th>Payload</th>
                <th>Response Code</th>
                <th>Size</th>
                <th>Timestamp</th>
            </tr>
"""
        
        for result in self.results[:100]:  # Limit to first 100 for performance
            severity_class = 'vuln-high' if result.response_code in [200, 301, 302] else 'vuln-medium'
            # Escape untrusted values (URLs/payloads contain '<', CRLF, etc.)
            # to prevent broken markup / self-XSS when the report is opened.
            url_cell = html_escape(result.url[:50]) + ('...' if len(result.url) > 50 else '')
            payload_cell = html_escape(result.payload[:40]) + ('...' if len(result.payload) > 40 else '')
            attack_cell = html_escape(result.attack_type)
            html += f"""
            <tr>
                <td>{url_cell}</td>
                <td><span class="attack-type">{attack_cell}</span></td>
                <td><span class="payload">{payload_cell}</span></td>
                <td class="{severity_class}">{result.response_code}</td>
                <td>{result.response_size}</td>
                <td class="timestamp">{result.timestamp.strftime("%H:%M:%S")}</td>
            </tr>
"""
        
        if len(self.results) > 100:
            html += f"""
            <tr>
                <td colspan="6" style="text-align: center; color: #7f8c8d;">
                    ... and {len(self.results) - 100} more results (see JSON/CSV for complete data)
                </td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        with open(self.html_output, 'w') as f:
            f.write(html)

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate summary statistics"""
        total_urls = len(set(r.url for r in self.results))
        total_vulnerabilities = len([r for r in self.results if r.is_vulnerable])
        
        # Get actual request counts from scanner if available
        from_scanner = hasattr(self, '_scanner_stats')
        
        return {
            'Total URLs Scanned': total_urls,
            'Total Requests': self._scanner_stats['total_attempted'] if from_scanner else len(self.results),
            'Vulnerabilities Found': total_vulnerabilities,
            'Success Rate': f"{self._scanner_stats['success_rate']:.1f}%" if from_scanner else f"{(total_vulnerabilities / len(self.results)) * 100:.1f}%" if self.results else "0%",
            'Unique Attack Types': len(set(r.attack_type for r in self.results))
        }

    def _group_vulnerabilities(self) -> Dict[str, List[ScanResult]]:
        """Group vulnerabilities by type"""
        grouped = {}
        for result in self.results:
            if result.is_vulnerable:
                if result.attack_type not in grouped:
                    grouped[result.attack_type] = []
                grouped[result.attack_type].append(result)
        return grouped

