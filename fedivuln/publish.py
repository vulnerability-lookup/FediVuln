import argparse
import json
from typing import Any
from urllib.parse import urljoin

import requests
from mastodon import Mastodon

from fedivuln import config

# Set up your Mastodon instance with access credentials
mastodon = Mastodon(
    client_id=config.mastodon_clientcred,
    access_token=config.mastodon_usercred,
    api_base_url=config.api_base_url,
)


# ### Templates

TEMPLATES = {
    "vulnerability": "You can now share your thoughts on vulnerability "
    "<VULNID> in Vulnerability-Lookup:\n<LINK>\n\n#VulnerabilityLookup #Vulnerability",
    "comment": "Vulnerability <VULNID> has received a comment on "
    "Vulnerability-Lookup:\n<LINK>\n\n#VulnerabilityLookup #Vulnerability",
    "bundle": "A new bundle, <BUNDLETITLE>, has been published "
    "on Vulnerability-Lookup:\n<LINK>\n\n#VulnerabilityLookup #Vulnerability",
}


def create_status_content(event_data: dict[str, Any], topic: str) -> str:
    """Generates a status update for posting based on the monitored topic."""
    status = TEMPLATES[topic]
    match topic:
        case "vulnerability":
            status = status.replace("<VULNID>", event_data["payload"]["vulnerability"])
        case "comment":
            status = status.replace("<VULNID>", event_data["payload"]["vulnerability"])
        case "bundle":
            status = status.replace("<BUNDLETITLE>", event_data["payload"]["name"])
        case _:
            pass
    status = status.replace("<LINK>", event_data["uri"])
    return status


# ### Streaming functions


def publish(message):
    mastodon.status_post(message)


def listen_to_http_event_stream(url, headers=None, params=None, topic="comment"):
    """
    Connects to a text/event-stream endpoint and displays incoming messages, including multiline data.

    Args:
        url (str): The URL of the event-stream endpoint.
        headers (dict): Optional headers for the request.
        params (dict): Optional query parameters for the request.
    """
    try:
        print("Connecting to stream. Listening for events...\n")
        # Open a streaming connection
        with requests.get(url, headers=headers, params=params, stream=True) as response:
            # Force the headers to be fetched immediately
            response.raise_for_status()  # Raise an error for non-200 responses

            # Accumulate data for multiline messages
            event_data = []

            for line in response.iter_lines(decode_unicode=True):
                if line:  # Non-empty line
                    if line.startswith("data:"):
                        # Remove "data:" and accumulate the rest of the line
                        event_data.append(line[5:].strip())
                    elif line.startswith("event:"):
                        event_type = line[6:].strip()
                        print(f"Event type: {event_type}")
                else:  # Empty line indicates the end of an event
                    if event_data:
                        # Join all accumulated lines into a single string
                        full_data = "\n".join(event_data)
                        try:
                            # Try to parse as JSON if possible
                            message = json.loads(full_data)
                            print(f"Received JSON message: {message}")
                            publish(create_status_content(message, topic))
                        except json.JSONDecodeError:
                            # Fallback to plain text
                            print(f"Received plain message: {full_data}")

                    # Reset accumulator for the next event
                    event_data = []

    except Exception as e:
        print(f"Error: {e}")


def main():
    # Point of entry in execution mode
    parser = argparse.ArgumentParser(prog="FediVuln-Publish")
    parser.add_argument(
        "-t",
        "--topic",
        dest="topic",
        default="comment",
        choices=["vulnerability", "comment", "bundle", "sighting"],
        help="The topic to subscribe to.",
    )

    arguments = parser.parse_args()

    combined = urljoin(config.vulnerability_lookup_base_url, "pubsub/subscribe/")
    full_url = urljoin(combined, arguments.topic)
    # headers = {"X-API-KEY": "YOUR_TOKEN"}
    listen_to_http_event_stream(full_url, topic=arguments.topic)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
