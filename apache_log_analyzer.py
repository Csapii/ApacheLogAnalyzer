# DoS detection uses per-second bucketing:
# timestamps are normalized to second precision to approximate request bursts.
# This allows detection of sudden traffic spikes per IP without storing raw events.
# Signature matching uses case-insensitive substring search over normalized request
# URI + query string. This is a simple baseline detector for known attack vectors.

import re
import sys
import argparse

from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, unquote
from collections import Counter, defaultdict

@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    uri: str
    query_string: str
    status_code: int

    def full_uri(self) -> str:
        if self.query_string:
            return f"{self.uri}?{self.query_string}"
        return self.uri

class SignatureDB:
    """
    Stores and matches security signatures against HTTP request data.

    Matching is case-insensitive and performed via substring search
    over full normalized URI + query string.
    """
    def __init__(self, path: str):
        self.signatures = []
        self._load(path)

    def _load(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.signatures = [
                    line.strip().lower()
                    for line in f
                    if line.strip()
                ]
        except FileNotFoundError:
            raise

    def matches(self, text: str) -> list[str]:
        text = text.lower()
        return [
            sig for sig in self.signatures
            if sig in text
        ]

class LogParser:
    """
    Parses Apache Combined Log Format into structured LogEntry objects.

    Responsibilities:
    - Validate log line format
    - Extract HTTP metadata
    - Normalize URI and query parameters
    """
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+) '
        r'(?P<ident>\S+) '
        r'(?P<authuser>\S+) '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) '
        r'(?P<size>\S+) '
        r'"(?P<referer>[^"]*)" '
        r'"(?P<user_agent>[^"]*)"'
    )

    def parse_line(self, line: str) -> LogEntry:
        match = self.LOG_PATTERN.match(line)
        if not match:
            raise ValueError("Invalid Combined Log Format")

        data = match.groupdict()

        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )

        parts = data["request"].split()
        if len(parts) != 3:
            raise ValueError("Malformed request field")

        method, full_uri, _ = parts
        parsed = urlparse(full_uri)

        return LogEntry(
            ip=data["ip"],
            timestamp=timestamp,
            method=method,
            uri=parsed.path,
            query_string=parsed.query,
            status_code=int(data["status"])
        )

class LogAnalyzer:
    """
    Core analysis engine.

    Performs:
    - Streaming log processing
    - Signature-based threat detection
    - DoS burst detection (per-second aggregation)
    - Statistical aggregation (IP, status codes, URI frequency)
    """

    def __init__(self, sigdb: SignatureDB):
        self.sigdb = sigdb

        self.ip_hits = Counter()
        self.status_codes = Counter()
        self.uri_hits = Counter()

        self.ip_time = defaultdict(lambda: Counter())

        self.threat_detected = False


    def detect_dos(self, threshold=20):
        detected = False

        for ip, times in self.ip_time.items():
            for ts, count in times.items():
                if count > threshold:
                    detected = True
                    print(
                        f"[DoS ALERT] {ip} -> {count} req @ {ts}",
                        file=sys.stderr
                    )

        return detected

    def process(self, entry: LogEntry):

        # stats
        self.ip_hits[entry.ip] += 1
        self.status_codes[f"{entry.status_code // 100}xx"] += 1
        self.uri_hits[entry.uri] += 1

        ts = entry.timestamp.replace(microsecond=0)
        self.ip_time[entry.ip][ts] += 1

        full_uri = entry.full_uri()
        full_uri = unquote(full_uri)

        hits = self.sigdb.matches(full_uri)

        if hits:
            self.threat_detected = True

            print(f"{entry.ip} {full_uri}")

            print(
                f"[ALERT] signature match: {hits}",
                file=sys.stderr
            )

    def report(self):

        print("\n=== STATISTICS ===", file=sys.stderr)

        print("\n[IP FREQUENCY]", file=sys.stderr)
        for ip, c in self.ip_hits.most_common():
            print(f"{ip}: {c}", file=sys.stderr)

        print("\n[STATUS CODES]", file=sys.stderr)
        for k, v in sorted(self.status_codes.items()):
            print(f"{k}: {v}", file=sys.stderr)

        print("\n[TOP 10 URIs]", file=sys.stderr)
        for uri, c in self.uri_hits.most_common(10):
            print(f"{uri}: {c}", file=sys.stderr)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("-d", "--database", required=True)

    args = parser.parse_args()

    try:
        sigdb = SignatureDB(args.database)
        analyzer = LogAnalyzer(sigdb)

        with open(args.logfile, "r", encoding="utf-8") as f:

            for i, line in enumerate(f, 1):

                line = line.strip()
                if not line:
                    continue

                try:
                    entry = LogParser().parse_line(line)
                    analyzer.process(entry)

                except Exception as e:
                    print(
                        f"[ERROR] line {i}: {e}",
                        file=sys.stderr
                    )

        analyzer.report()

        dos = analyzer.detect_dos()

        if analyzer.threat_detected or dos:
            sys.exit(1)

        sys.exit(0)

    except FileNotFoundError as e:
        print(f"[FATAL] missing file: {e}", file=sys.stderr)
        sys.exit(2)

    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()