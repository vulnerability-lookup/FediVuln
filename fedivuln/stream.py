import argparse
import re
import sys

from mastodon import Mastodon, StreamListener  # type: ignore[import-untyped]

from fedivuln import config

mastodon = Mastodon(
    client_id="mastodon_clientcred.secret",
    access_token="mastodon_usercred.secret",
    api_base_url=config.api_base_url,
)


# Listener class for handling stream events
class VulnStreamListener(StreamListener):
    # Regular expression to match CVE, GHSA, and PySec IDs
    cve_pattern = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
    ghsa_pattern = re.compile(
        r"GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}", re.IGNORECASE
    )
    pysec_pattern = re.compile(r"PYSEC-\d{4}-\d{2,5}", re.IGNORECASE)

    # When a new status (post) is received
    def on_update(self, status):
        print("New status received.")
        content = status["content"]
        if (
            self.cve_pattern.search(content)
            or self.ghsa_pattern.search(content)
            or self.pysec_pattern.search(content)
        ):
            print("Vulnerability detected:")
            print(status)  # Prints the full HTML content of the status
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


# Instantiate the listener
listener = VulnStreamListener()


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

    arguments = parser.parse_args()

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
