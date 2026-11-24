
import sqlite3
from pathlib import Path

# Database location
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "threats.db"


def get_connection():
    """Create a database connection."""
    return sqlite3.connect(DB_PATH)


def initialize_database():
    """Create threat database table if it does not exist."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                threat_type TEXT DEFAULT 'Phishing',
                source TEXT DEFAULT 'Local Database'
            )
        """)

        connection.commit()


def add_threat(url, threat_type="Phishing", source="Local Database"):
    """Add a known threat URL."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT OR IGNORE INTO threats
            (url, threat_type, source)
            VALUES (?, ?, ?)
        """, (url.strip().lower(), threat_type, source))

        connection.commit()


def check_threat(url):
    """Check whether a URL exists in our database."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT threat_type, source
            FROM threats
            WHERE url = ?
        """, (url.strip().lower(),))

        result = cursor.fetchone()

    if result:
        return {
            "found": True,
            "threat_type": result[0],
            "source": result[1]
        }

    return {
        "found": False,
        "threat_type": None,
        "source": None
    }


def get_all_threats():
    """Return all stored threat records."""

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT id, url, threat_type, source
            FROM threats
            ORDER BY id DESC
        """)

        return cursor.fetchall()
