# Simple Log Analyzer (DoS + Signature Detection)

This project is a basic security log analyzer for Apache-style web server logs.

It can:
- Parse Apache Combined Log Format
- Detect suspicious requests using signature matching
- Detect basic DoS (traffic spikes per IP per second)
- Generate simple statistics (IP frequency, status codes, URI usage)

---

## How it works

The tool processes a log file line by line:

1. Parses each log entry into structured data
2. Tracks:
   - number of requests per IP
   - HTTP status codes
   - most requested URIs
3. Detects:
   - known attack patterns (signature database)
   - request spikes per second (possible DoS)

---

## Requirements

- Python 3.8+

No external libraries required.

---

## Usage

Run the analyzer like this:

```bash
python3 apache_log_analyzer.py apache_logs -d signatures.txt 