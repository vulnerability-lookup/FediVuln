import argparse
import json
import sys
from datetime import datetime

from mastodon import Mastodon, StreamListener
from pyvulnerabilitylookup import PyVulnerabilityLookup

from fedivuln import config
from fedivuln.monitoring import heartbeat, log


# Custom encoder for datetime
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()  # Convert datetime to ISO format string
        return super().default(obj)


mastodon = Mastodon(
    client_id=config.mastodon_clientcred,
    access_token=config.mastodon_usercred,
    api_base_url=config.api_base_url,
)


# Listener class for handling stream events
class VulnStreamListener(StreamListener):
    def __init__(self, push_sighting: bool = False):
        self.push_sighting = push_sighting

    # When a new status (post) is received
    def on_update(self, status):
        print("New status received.")
        if status["edited_at"] is not None:
            print("Edit of a previous status. Ignoring.")
            return
        content = status["content"]
        matches = config.vulnerability_patterns.findall(
            content
        )  # Find all matches in the content
        # Flatten the list of tuples to get only non-empty matched strings
        vulnerability_ids = [
            match for match_tuple in matches for match in match_tuple if match
        ]
        vulnerability_ids = remove_case_insensitive_duplicates(vulnerability_ids)
        if vulnerability_ids:
            print("Vulnerability IDs detected:", ", ".join(vulnerability_ids))
            if self.push_sighting:
                push_sighting_to_vulnerability_lookup(
                    status["uri"], vulnerability_ids
                )  # Push the sighting to Vulnerability-Lookup
            # if self.push_status:
            #     push_status_to_vulnerability_lookup(
            #         status, vulnerability_ids
            #     )  # Push the status to Vulnerability-Lookup
        else:
            print("No ID detected. Ignoring.")

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
        log("error", f"Stream aborted with error: {err}")

    def handle_heartbeat(self):
        heartbeat(process_name="process_heartbeat_FediVuln")


def remove_case_insensitive_duplicates(input_list):
    """Remove duplicates in a list, ignoring case.
    This approach preserves the last occurrence of each unique item based on
    lowercase equivalence. The dictionary keys are all lowercase to ensure
    case-insensitive comparison, while the original case is preserved in the output.
    """
    return list({item.lower(): item for item in input_list}.values())


def push_sighting_to_vulnerability_lookup(status_uri, vulnerability_ids):
    """Create a sighting from an incoming status and push it to the Vulnerability-Lookup instance."""
    print("Pushing sighting to Vulnerability-Lookup…")
    vuln_lookup = PyVulnerabilityLookup(
        config.vulnerability_lookup_base_url, token=config.vulnerability_auth_token
    )
    for vuln in vulnerability_ids:
        # Create the sighting
        sighting = {"type": "seen", "source": status_uri, "vulnerability": vuln}

        # Post the JSON to Vulnerability-Lookup
        try:
            r = vuln_lookup.create_sighting(sighting=sighting)
            if "message" in r:
                print(r["message"])
        except Exception as e:
            print(
                f"Error when sending POST request to the Vulnerability-Lookup server:\n{e}"
            )
            log(
                "error",
                f"Error when sending POST request to the Vulnerability-Lookup server: {e}",
            )


def main():
    parser = argparse.ArgumentParser(
        prog="FediVuln-Stream", description="Allows access to the streaming API."
    )
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
        "--push-sighting",
        action="store_true",
        help="Push the sightings to Vulnerability-Lookup.",
    )
    # parser.add_argument(
    #     "--push-status",
    #     action="store_true",
    #     help="Push the status to Vulnerability-Lookup.",
    # )

    arguments = parser.parse_args()

    # Instantiate the listener
    listener = VulnStreamListener(push_sighting=arguments.push_sighting)

    if arguments.user:
        print("Starting Mastodon user stream…")
        mastodon.stream_user(listener)
    elif arguments.public:
        print("Starting Mastodon local public stream…")
        mastodon.stream_public(listener)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
