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

    def __str__(self) -> str:
        return (
            f"[{self.timestamp}] "
            f"{self.ip} "
            f"{self.method} "
            f"{self.full_uri()} "
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
    Loads attack signatures from a text file.
    """

    def __init__(self, path: str):
        self.signatures = []
        self.load_signatures(path)

    def load_signatures(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as file:
                for line in file:
                    sig = line.strip().lower()

                    if sig:
                        self.signatures.append(sig)

        except FileNotFoundError:
            raise FileNotFoundError(
                f"Signature file not found: {path}"
            )

    def matches(self, text: str):
        text = text.lower()

        return [
            sig
            for sig in self.signatures
            if sig in text
        ]


class LogParser:
    """
    Parses Apache Combined Log Format.
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
            raise ValueError("Invalid log format")

        data = match.groupdict()

        timestamp = datetime.strptime(
            data["timestamp"],
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


def iter_log_entries(path: str):
    """
    Generator-based streaming parser.
    """

    parser = LogParser()

    with open(path, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                yield parser.parse_line(line)

            except Exception as error:
                print(
                    f"[ERROR] line {line_number}: {error}",
                    file=sys.stderr
                )


class LogAnalyzer:
    """
    Analyzes:
    - attackers
    - URI usage
    - status groups
    - signature matches
    - DoS bursts
    """

    def __init__(self, signature_db: SignatureDB):
        self.signature_db = signature_db

        self.ip_counts = Counter()
        self.status_counts = Counter()
        self.uri_counts = Counter()

        self.requests_per_second = defaultdict(Counter)

        self.threat_found = False

    def process(self, entry: LogEntry):
        self.ip_counts[entry.ip] += 1

        status_group = f"{str(entry.status_code)[0]}xx"
        self.status_counts[status_group] += 1

        self.uri_counts[entry.uri] += 1

        second_bucket = entry.timestamp.replace(
            microsecond=0
        )

        self.requests_per_second[entry.ip][
            second_bucket
        ] += 1

        full_uri = unquote(entry.full_uri())

        matched = self.signature_db.matches(full_uri)

        if matched:
            self.threat_found = True

            print(
                f"{entry.ip} {full_uri}"
            )

            print(
                f"[ALERT] signature match: {matched}",
                file=sys.stderr
            )

    def detect_dos(
        self,
        threshold: int = 20
    ) -> bool:

        detected = False

        for ip, timestamps in self.requests_per_second.items():

            for ts, count in timestamps.items():

                if count > threshold:
                    detected = True

                    print(
                        f"[DoS ALERT] "
                        f"{ip} -> {count} requests at {ts}",
                        file=sys.stderr
                    )

        return detected

    def report(self):
        print(
            "\n=== STATISTICS ===",
            file=sys.stderr
        )

        print(
            "\nTOP 3 ATTACKERS:",
            file=sys.stderr
        )

        for ip, count in self.ip_counts.most_common(3):
            print(
                f"{ip}: {count}",
                file=sys.stderr
            )

        print(
            "\nSTATUS GROUPS:",
            file=sys.stderr
        )

        for status, count in sorted(
            self.status_counts.items()
        ):
            print(
                f"{status}: {count}",
                file=sys.stderr
            )

        print(
            "\nTOP 10 URIs:",
            file=sys.stderr
        )

        for uri, count in self.uri_counts.most_common(10):
            print(
                f"{uri}: {count}",
                file=sys.stderr
            )


def main():
    parser = argparse.ArgumentParser(
        description="Apache Log Security Scanner"
    )

    parser.add_argument(
        "--scan",
        required=True,
        help="Apache log file"
    )

    parser.add_argument(
        "-d",
        "--database",
        required=True,
        help="Signature database"
    )

    args = parser.parse_args()

    try:
        signature_db = SignatureDB(
            args.database
        )

        analyzer = LogAnalyzer(
            signature_db
        )

        for entry in iter_log_entries(args.scan):
            analyzer.process(entry)

        analyzer.report()

        dos_detected = analyzer.detect_dos()

        if analyzer.threat_found or dos_detected:
            sys.exit(1)

        sys.exit(0)

    except FileNotFoundError as error:
        print(
            f"[FATAL] {error}",
            file=sys.stderr
        )
        sys.exit(2)

    except Exception as error:
        print(
            f"[FATAL] {error}",
            file=sys.stderr
        )
        sys.exit(2)


if __name__ == "__main__":
    main()