from apache_log_analyzer import LogParser, SignatureDB, LogAnalyzer


def test_log_parsing_normalization():
    parser = LogParser()

    line = (
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /test.php?id=1 HTTP/1.1" 200 123 "-" "-"'
    )

    entry = parser.parse_line(line)

    assert entry.ip == "127.0.0.1"
    assert entry.method == "GET"
    assert entry.uri == "/test.php"
    assert entry.query_string == "id=1"
    assert entry.status_code == 200


def test_signature_matching():
    db = SignatureDB.__new__(SignatureDB)
    db.signatures = ["union select", "../etc/passwd"]

    hits = db.matches("/index.php?x=union select 1")
    assert "union select" in hits


def test_statistics_collection():
    db = SignatureDB.__new__(SignatureDB)
    db.signatures = []

    analyzer = LogAnalyzer(db)

    entry = LogParser().parse_line(
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /a HTTP/1.1" 200 1 "-" "-"'
    )

    analyzer.process(entry)

    assert analyzer.ip_hits["127.0.0.1"] == 1
    assert analyzer.status_codes["2xx"] == 1
    assert analyzer.uri_hits["/a"] == 1