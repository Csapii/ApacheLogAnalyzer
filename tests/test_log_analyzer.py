import unittest
from apache_log_analyzer import LogParser, SignatureDB, LogAnalyzer


class TestLogParser(unittest.TestCase):

    def test_log_parsing_normalization(self):
        parser = LogParser()

        line = (
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /test.php?id=1 HTTP/1.1" 200 123 "-" "-"'
        )

        entry = parser.parse_line(line)

        self.assertEqual(entry.ip, "127.0.0.1")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.uri, "/test.php")
        self.assertEqual(entry.query_string, "id=1")
        self.assertEqual(entry.status_code, 200)

    def test_invalid_log_line(self):
        parser = LogParser()

        with self.assertRaises(ValueError):
            parser.parse_line("this is not an apache log")

    def test_malformed_request_line(self):
        parser = LogParser()

        line = (
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET_ONLY" 200 123 "-" "-"'
        )

        with self.assertRaises(ValueError):
            parser.parse_line(line)

    def test_full_uri_with_query_string(self):
        parser = LogParser()

        entry = parser.parse_line(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /test.php?id=123 HTTP/1.1" '
            '200 1 "-" "-"'
        )

        self.assertEqual(
            entry.full_uri(),
            "/test.php?id=123"
        )

    def test_full_uri_without_query_string(self):
        parser = LogParser()

        entry = parser.parse_line(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /test.php HTTP/1.1" '
            '200 1 "-" "-"'
        )

        self.assertEqual(
            entry.full_uri(),
            "/test.php"
        )


class TestSignatureDB(unittest.TestCase):

    def test_signature_matching(self):
        db = SignatureDB.__new__(SignatureDB)
        db.signatures = [
            "union select",
            "../etc/passwd"
        ]

        hits = db.matches(
            "/index.php?x=union select 1"
        )

        self.assertIn(
            "union select",
            hits
        )

    def test_case_insensitive_matching(self):
        db = SignatureDB.__new__(SignatureDB)
        db.signatures = ["union select"]

        hits = db.matches(
            "/index.php?q=UNION SELECT password"
        )

        self.assertEqual(
            hits,
            ["union select"]
        )

    def test_multiple_signature_matches(self):
        db = SignatureDB.__new__(SignatureDB)

        db.signatures = [
            "union select",
            "../etc/passwd"
        ]

        hits = db.matches(
            "/x?y=union select&z=../etc/passwd"
        )

        self.assertEqual(
            len(hits),
            2
        )

        self.assertIn(
            "union select",
            hits
        )

        self.assertIn(
            "../etc/passwd",
            hits
        )


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.db = SignatureDB.__new__(SignatureDB)
        self.db.signatures = []

        self.parser = LogParser()
        self.analyzer = LogAnalyzer(
            self.db
        )

    def test_statistics_collection(self):
        entry = self.parser.parse_line(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /a HTTP/1.1" 200 1 "-" "-"'
        )

        self.analyzer.process(entry)

        self.assertEqual(
            self.analyzer.ip_counts["127.0.0.1"],
            1
        )

        self.assertEqual(
            self.analyzer.status_counts["2xx"],
            1
        )

        self.assertEqual(
            self.analyzer.uri_counts["/a"],
            1
        )

    def test_status_grouping_4xx(self):
        entry = self.parser.parse_line(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /missing HTTP/1.1" '
            '404 1 "-" "-"'
        )

        self.analyzer.process(entry)

        self.assertEqual(
            self.analyzer.status_counts["4xx"],
            1
        )

    def test_status_grouping_5xx(self):
        entry = self.parser.parse_line(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /error HTTP/1.1" '
            '500 1 "-" "-"'
        )

        self.analyzer.process(entry)

        self.assertEqual(
            self.analyzer.status_counts["5xx"],
            1
        )

    def test_threat_flag_set(self):
        self.db.signatures = [
            "union select"
        ]

        analyzer = LogAnalyzer(
            self.db
        )

        entry = self.parser.parse_line(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
            '"GET /x?q=union%20select HTTP/1.1" '
            '200 1 "-" "-"'
        )

        analyzer.process(entry)

        self.assertTrue(
            analyzer.threat_found
        )

    def test_dos_detected(self):
        line = (
            '127.0.0.1 - - '
            '[10/Oct/2000:13:55:36 +0000] '
            '"GET / HTTP/1.1" 200 1 "-" "-"'
        )

        for _ in range(25):
            self.analyzer.process(
                self.parser.parse_line(line)
            )

        self.assertTrue(
            self.analyzer.detect_dos(
                threshold=20
            )
        )

    def test_dos_not_detected(self):
        line = (
            '127.0.0.1 - - '
            '[10/Oct/2000:13:55:36 +0000] '
            '"GET / HTTP/1.1" 200 1 "-" "-"'
        )

        for _ in range(5):
            self.analyzer.process(
                self.parser.parse_line(line)
            )

        self.assertFalse(
            self.analyzer.detect_dos(
                threshold=20
            )
        )


if __name__ == "__main__":
    unittest.main()