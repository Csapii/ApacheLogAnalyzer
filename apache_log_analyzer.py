import re
import sys
import argparse

from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    uri: str
    query_string: str
    status_code: int

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
    
class LogParser:

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
            raise ValueError(
                "Line does not match Combined Log Format"
            )

        data = match.groupdict()

        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )

        # Request parsing
        request_parts = data["request"].split()

        if len(request_parts) != 3:
            raise ValueError(
                "Malformed HTTP request field"
            )

        method, full_uri, _ = request_parts

        parsed_uri = urlparse(full_uri)

        uri = parsed_uri.path
        query_string = parsed_uri.query

        status_code = int(data["status"])

        return LogEntry(
            ip=data["ip"],
            timestamp=timestamp,
            method=method,
            uri=uri,
            query_string=query_string,
            status_code=status_code
        )
    
    def detect_bursts(self, ip_counter: dict, threshold: int = 20):
        for ip, timestamps in ip_counter.items():
            for ts, count in timestamps.items():
                if count > threshold:
                    print(f"[DoS ALERT] {ip} sent {count} requests at {ts}")


    def parse_file(self, file_path: str, sigdb: SignatureDB):
        ip_counter = {}  # for DoS detection

        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = self.parse_line(line)
                    full_uri = entry.uri
                    if entry.query_string:
                        full_uri += "?" + entry.query_string

                    # Signature detection
                    hits = sigdb.matches(full_uri)
                    if hits:
                        print(f"[ALERT] Signature match from {entry.ip}: {hits}")

                    # DoS counter
                    ts = entry.timestamp.replace(microsecond=0)
                    ip_counter.setdefault(entry.ip, {})
                    ip_counter[entry.ip][ts] = ip_counter[entry.ip].get(ts, 0) + 1

                    print(entry)

                except ValueError as e:
                    print(f"[ERROR] Line {line_number}: {e}", file=sys.stderr)

        self.detect_bursts(ip_counter)

                    
class SignatureDB:
    def __init__(self, path: str):
        self.signatures = set()
        self._load(path)

    def _load(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                sig = line.strip()
                if sig:
                    self.signatures.add(sig.lower())

    def matches(self, text: str) -> list[str]:
        text = text.lower()
        return [sig for sig in self.signatures if sig in text]



def main():

    parser = argparse.ArgumentParser(
        description="Apache Combined Log Format parser"
    )

    parser.add_argument(
        "logfile",
        help="Path to Apache log file"
    )
    parser.add_argument(
        "--database",
        "-d",
        help="Path to signature database file",
        required=True
    )


    args = parser.parse_args()

    log_parser = LogParser()
    log_parser.parse_file(args.logfile)


if __name__ == "__main__":
    main()