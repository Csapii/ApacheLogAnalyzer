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
        """Return URI with query string if it exists."""
        if self.query_string != "":
            return self.uri + "?" + self.query_string
        return self.uri
    
    def __str__(self) -> str:
        qs = f"?{self.query_string}" if self.query_string else ""
        return (
            f"[{self.timestamp}] "
            f"{self.ip} "
            f"{self.method} "
            f"{self.uri}{qs} "
            f"-> {self.status_code}"
        )
    def __repr__(self) -> str:
        return (
            f"LogEntry(ip={self.ip!r}, "
            f"timestamp={self.timestamp!r}, "
            f"method={self.method!r}, "
            f"uri={self.uri!r}, "
            f"query_string={self.query_string!r}, "
            f"status_code={self.status_code!r})"
        )

class SignatureDB:
    """
    Loads known attack signatures and checks if they appear in requests.
    """

    def __init__(self, path: str):
        self.signatures = []
        self.load_signatures(path)

    def load_signatures(self, path: str):
        """Read signature file into memory."""
        try:
            file = open(path, "r", encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(f"Signature file not found: {path}")

        lines = file.readlines()
        file.close()

        for line in lines:
            line = line.strip()
            if line != "":
                self.signatures.append(line.lower())

    def matches(self, text: str):
        """
        Return all signatures found in the given text.
        Case-insensitive substring matching.
        """
        text = text.lower()

        matched = []

        for sig in self.signatures:
            if sig in text:
                matched.append(sig)

        return matched

class LogParser:
    """
    Converts raw Apache logs into structured LogEntry objects.
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
        """Parse a single log line into LogEntry."""

        match = self.LOG_PATTERN.match(line)
        if match is None:
            raise ValueError("Invalid log format")

        data = match.groupdict()

        timestamp_text = data["timestamp"]
        timestamp = datetime.strptime(
            timestamp_text,
            "%d/%b/%Y:%H:%M:%S %z"
        )

        request_parts = data["request"].split()

        if len(request_parts) != 3:
            raise ValueError("Malformed request line")

        method = request_parts[0]
        full_url = request_parts[1]

        parsed_url = urlparse(full_url)

        return LogEntry(
            ip=data["ip"],
            timestamp=timestamp,
            method=method,
            uri=parsed_url.path,
            query_string=parsed_url.query,
            status_code=int(data["status"])
        )

class LogAnalyzer:
    """
    Analyzes logs for:
    - IP statistics
    - status codes
    - URI frequency
    - signature-based threats
    - DoS burst detection
    """

    def __init__(self, signature_db: SignatureDB):
        self.signature_db = signature_db

        self.ip_counts = Counter()
        self.status_counts = Counter()
        self.uri_counts = Counter()

        # ip -> timestamp -> count
        self.requests_per_second = defaultdict(lambda: Counter())

        self.threat_found = False

    def process(self, entry: LogEntry):
        """Process one log entry."""

        self.ip_counts[entry.ip] += 1

        status_group = str(entry.status_code)[0] + "xx"
        self.status_counts[status_group] += 1

        self.uri_counts[entry.uri] += 1

        timestamp = entry.timestamp.replace(microsecond=0)
        self.requests_per_second[entry.ip][timestamp] += 1

        full_uri = entry.full_uri()
        full_uri = unquote(full_uri)

        matched_signatures = self.signature_db.matches(full_uri)

        if len(matched_signatures) > 0:
            self.threat_found = True

            print(entry.ip + " " + full_uri)

            print(
                "[ALERT] signature match: " + str(matched_signatures),
                file=sys.stderr
            )

    def detect_dos(self, threshold: int = 20) -> bool:
        """
        Detect burst traffic per IP per second.
        """
        detected = False

        for ip in self.requests_per_second:
            timestamps = self.requests_per_second[ip]

            for ts in timestamps:
                count = timestamps[ts]

                if count > threshold:
                    detected = True
                    print(
                        f"[DoS ALERT] {ip} -> {count} requests at {ts}",
                        file=sys.stderr
                    )

        return detected

    def report(self):
        """Print summary statistics."""

        print("\n=== STATISTICS ===", file=sys.stderr)

        print("\nIP FREQUENCY:", file=sys.stderr)
        for ip, count in self.ip_counts.most_common():
            print(ip + ": " + str(count), file=sys.stderr)

        print("\nSTATUS CODES:", file=sys.stderr)
        for status, count in sorted(self.status_counts.items()):
            print(status + ": " + str(count), file=sys.stderr)

        print("\nTOP URIs:", file=sys.stderr)
        top_uris = self.uri_counts.most_common(10)

        for uri, count in top_uris:
            print(uri + ": " + str(count), file=sys.stderr)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("-d", "--database", required=True)

    args = parser.parse_args()

    try:
        signature_db = SignatureDB(args.database)
        analyzer = LogAnalyzer(signature_db)

        log_file = open(args.logfile, "r", encoding="utf-8")

        line_number = 0

        for line in log_file:
            line_number += 1
            line = line.strip()

            if line == "":
                continue

            try:
                parser = LogParser()
                entry = parser.parse_line(line)
                analyzer.process(entry)

            except Exception as error:
                print(
                    f"[ERROR] line {line_number}: {error}",
                    file=sys.stderr
                )

        log_file.close()

        analyzer.report()

        dos_detected = analyzer.detect_dos()

        if analyzer.threat_found or dos_detected:
            sys.exit(1)

        sys.exit(0)

    except FileNotFoundError as error:
        print(f"[FATAL] missing file: {error}", file=sys.stderr)
        sys.exit(2)

    except Exception as error:
        print(f"[FATAL] {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()