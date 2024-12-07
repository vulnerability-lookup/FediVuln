import argparse
import json
from typing import Any
from urllib.parse import urljoin

import requests
from mastodon import Mastodon

from fedivuln import config

# Set up your Mastodon instance with access credentials
if config.mastodon_clientcred_push and config.mastodon_usercred_push:
    client_id = config.mastodon_clientcred_push
    access_token = config.mastodon_usercred_push
else:
    client_id = config.mastodon_clientcred
    access_token = config.mastodon_usercred

mastodon = Mastodon(
    client_id=client_id,
    access_token=access_token,
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
    status = TEMPLATES.get(topic, "")
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


def publish(message: str) -> None:
    mastodon.status_post(message)


def listen_to_http_event_stream(url, headers=None, params=None, topic="comment"):
    """
    Connects to a text/event-stream endpoint and displays incoming messages.

    Args:
        url (str): The URL of the event-stream endpoint.
        headers (dict): Optional headers for the request.
        params (dict): Optional query parameters for the request.
        topic (str): Topic for creating status content (optional).
    """
    try:
        # Open a streaming connection
        with requests.get(url, headers=headers, params=params, stream=True) as response:
            if response.status_code != 200:
                print(f"Error: Received status code {response.status_code}")
                return

            print("Connected to stream. Listening for events...\n")

            # Accumulate data for multiline messages
            # event_data = []
            # event_type = None

            for line in response.iter_lines(decode_unicode=True):
                if line:
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        message = json.loads(data)
                        print(message)
                        # publish(create_status_content(message, topic))
                # if line:  # Non-empty line
                #     if line.startswith("data:"):
                #         # Remove "data:" and accumulate the rest of the line
                #         event_data.append(line[5:].strip())
                #     elif line.startswith("event:"):
                #         # Capture the event type
                #         event_type = line[6:].strip()
                #     elif line.startswith(":"):
                #         # Skip comment lines (lines starting with ':')
                #         continue
                # else:  # Empty line indicates the end of an event
                #     if event_data:
                #         # Join all accumulated lines into a single string
                #         full_data = "\n".join(event_data)
                #         try:
                #             # Try to parse as JSON if possible
                #             message = json.loads(full_data)
                #             #print(f"Event Type: {event_type if event_type else 'default'}")
                #             #print(f"Received JSON message: {message}")
                #             # publish(create_status_content(message, topic))
                #         except json.JSONDecodeError:
                #             # Fallback to plain text
                #             pass
                #             #print(f"Received plain message: {full_data}")

                #         # Reset accumulator for the next event
                #         event_data = []
                #         event_type = None
    except Exception as e:
        print(f"Error: {e}")


def main():
    """Parsing of arguments."""
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
    headers = {"X-API-KEY": config.vulnerability_auth_token}
    listen_to_http_event_stream(full_url, headers=headers, topic=arguments.topic)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
