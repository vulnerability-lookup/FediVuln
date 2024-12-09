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
    Connects to a text/event-stream endpoint and processes incoming messages.

    Args:
        url (str): The URL of the event-stream endpoint.
        headers (dict): Optional headers for the request.
        params (dict): Optional query parameters for the request.
        topic (str): Topic for filtering or processing messages (optional).
    """
    try:
        print("Connecting to the event stream...")
        with requests.get(
            url, headers=headers, params=params, stream=True, timeout=None
        ) as response:
            if response.status_code != 200:
                print(f"Error: Received status code {response.status_code}")
                return

            print(f"Connected to the topic '{topic}'. Listening for events...\n")

            for line in response.iter_lines(decode_unicode=True):
                if line.startswith("data:"):
                    # Extract and process the data part
                    data_line = line[5:].strip()
                    try:
                        # Attempt to parse the data as JSON
                        message = json.loads(data_line)
                        print("Received JSON message:")
                        print(message)
                        # publish(create_status_content(message, topic))
                    except json.JSONDecodeError:
                        # Handle plain text messages
                        print(f"Received plain message: {data_line}")

    except requests.exceptions.RequestException as req_err:
        print(f"Request error: {req_err}")
    except KeyboardInterrupt:
        print("\nStream interrupted by user. Closing connection.")
    except Exception as e:
        print(f"Unexpected error: {e}")


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
