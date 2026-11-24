
from modules.threat_database import get_connection


def initialize_scan_history():
    """Create scan history table if it does not exist."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                phishing_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.commit()


def save_scan(url, prediction, phishing_score, risk_level):
    """Save one URL scan in the database."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO scan_history
            (url, prediction, phishing_score, risk_level)
            VALUES (?, ?, ?, ?)
        """, (url, prediction, phishing_score, risk_level))

        connection.commit()


def get_scan_history():
    """Return the latest 100 scanned URLs."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT id, url, prediction, phishing_score,
                   risk_level, scan_time
            FROM scan_history
            ORDER BY id DESC
            LIMIT 100
        """)

        return cursor.fetchall()
