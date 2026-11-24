
from modules.threat_database import (
    initialize_database,
    add_threat,
    check_threat,
    get_all_threats
)

# Initialize database
initialize_database()

print("Database initialized successfully!")

# Add a sample test URL
sample_url = "http://example-test-phishing.com/login"

add_threat(
    sample_url,
    threat_type="Phishing",
    source="Demo Test Record"
)

print("\nChecking sample URL...")

result = check_threat(sample_url)

print(result)

print("\nAll stored threat records:")

for threat in get_all_threats():
    print(threat)

print("\nDatabase test completed!")
