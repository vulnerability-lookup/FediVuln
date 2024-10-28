import argparse
import re
import sys
import urllib.parse

import requests
from mastodon import Mastodon, StreamListener

from fedivuln import config

mastodon = Mastodon(
    client_id="mastodon_clientcred.secret",
    access_token="mastodon_usercred.secret",
    api_base_url=config.api_base_url,
)


# Listener class for handling stream events
class VulnStreamListener(StreamListener):
    def __init__(self, sighting: bool = False):
        # Regular expression to match CVE, GHSA, and PySec IDs
        self.vulnerability_pattern = re.compile(
            r"\b(CVE-\d{4}-\d{4,})\b"  # CVE pattern
            r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"  # GHSA pattern
            r"|\b(PYSEC-\d{4}-\d{2,5})\b",  # PYSEC pattern
            re.IGNORECASE,
        )
        self.sighting = sighting

    # When a new status (post) is received
    def on_update(self, status):
        print("New status received.")
        content = status["content"]
        matches = self.vulnerability_pattern.findall(
            content
        )  # Find all matches in the content
        # Flatten the list of tuples to get only non-empty matched strings
        vulnerability_ids = [
            match for match_tuple in matches for match in match_tuple if match
        ]
        if vulnerability_ids:
            print("Vulnerability IDs detected:")
            print("Vulnerability IDs found:", ", ".join(vulnerability_ids))
            print(status)  # Prints the full status
            if self.sighting:
                push_to_vulnerability_lookup(
                    vulnerability_ids
                )  # Push a sighting to Vulnerability Lookup
        else:
            print("Ignoring.")

    # When a new notification is received (e.g., mention, follow, boost, favorite)
    def on_notification(self, notification):
        print("New notification received:")
        print(notification["type"], notification["account"]["acct"])

    # When a new direct message is received
    def on_direct_message(self, message):
        print("New direct message received:")
        print(message["content"])  # This contains the message content

    # Handle any errors in streaming
    def on_abort(self, err):
        print("Stream aborted with error:", err)


def push_to_vulnerability_lookup(vulnerability_ids):
    """Create a sighting from an incoming status and push it to the Vulnerability Lookup instance."""
    print("Pushing sighting to Vulnerability Lookup...")
    headers_json = {
        "Content-Type": "application/json",
        "accept": "application/json",
        "X-API-KEY": f" {config.vulnerability_auth_token}",
    }
    sighting = {"type": "seen", "vulnerability": vulnerability_ids[0]}
    try:
        r = requests.post(
            urllib.parse.urljoin(config.vulnerability_lookup_base_url, "sighting/"),
            json=sighting,
            headers=headers_json,
        )
        if r.status_code not in (200, 201):
            print(
                f"Error when sending POST request to the Vulnerability Lookup server: {r.reason}"
            )
    except requests.exceptions.ConnectionError as e:
        print(
            f"Error when sending POST request to the Vulnerability Lookup server:\n{e}"
        )


def main():
    parser = argparse.ArgumentParser(prog="FediVuln-Stream")
    parser.add_argument(
        "--user",
        action="store_true",
        help="Streams events that are relevant to the authorized user, i.e. home timeline and notifications.",
    )
    parser.add_argument(
        "--public",
        action="store_true",
        help="Streams public events.",
    )
    parser.add_argument(
        "--sighting",
        action="store_true",
        help="Push the sightings to Vulnerability Lookup.",
    )

    arguments = parser.parse_args()

    # Instantiate the listener
    listener = VulnStreamListener(sighting=arguments.sighting)

    if arguments.user:
        print("Starting user stream...")
        mastodon.stream_user(listener)
    elif arguments.public:
        print("Starting local public stream...")
        mastodon.stream_public(listener, remote=True)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
