import argparse
import asyncio
import json
from datetime import datetime
from urllib.parse import urljoin

import requests
import valkey
from mastodon import Mastodon
from mastodon.errors import MastodonAPIError

from fedivuln import config
from fedivuln.monitoring import heartbeat, log
from fedivuln.utils import (
    classify_vulnerability_severity,
    get_vendor_product_cve,
    truncate,
)

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


MAX_STATUS_LENGTH = 500


def create_status_content_sync(event_data: str, topic: str) -> str:
    """Sync wrapper around async create_status_content()."""
    return asyncio.run(create_status_content(event_data, topic))


async def create_status_content(event_data: str, topic: str) -> str:
    """Generates a status update for posting based on the monitored topic.

    Async because it calls classify_vulnerability_severity.
    Ensures the final status never exceeds MAX_STATUS_LENGTH.
    """
    event_dict = json.loads(event_data)
    status_template = config.templates.get(topic, "")

    match topic:
        case "vulnerability":
            try:
                # Skip if updated != published
                if (
                    event_dict["cveMetadata"]["datePublished"]
                    != event_dict["cveMetadata"]["dateUpdated"]
                ):
                    return ""

                vendor, product = get_vendor_product_cve(event_dict)[0]
                cve_id = event_dict["cveMetadata"]["cveId"]

                description = (
                    event_dict.get("containers", {})
                    .get("cna", {})
                    .get("descriptions", [{}])[0]
                    .get("value", "")
                )

                # Parse ISO 8601 date string
                published_raw = event_dict["cveMetadata"]["datePublished"]
                try:
                    published_dt = datetime.fromisoformat(
                        published_raw.replace("Z", "+00:00")
                    )
                    # Format as YYYY-MM-DD HH:MM
                    published_str = published_dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    # Fallback: use raw string if parsing fails
                    published_str = published_raw

                # Build base status WITHOUT description or VLAI score
                status = (
                    status_template.replace("<PUBLISHED>", published_str)
                    .replace("<VULNID>", cve_id)
                    .replace("<LINK>", f"https://vulnerability.circl.lu/vuln/{cve_id}")
                    .replace("<VENDOR>", vendor)
                    .replace("<PRODUCT>", product)
                )

                # Compute VLAI score
                vla_score_str = ""
                if description:
                    severity = await classify_vulnerability_severity(description)
                    if severity:
                        vla_score_str = f"{severity['severity']} (confidence: {severity['confidence']:.2f})"
                    else:
                        vla_score_str = "N/A"

                status = status.replace("<VLAI-SCORE>", vla_score_str)

                # Compute remaining space for description
                remaining = MAX_STATUS_LENGTH - len(status) + len("<DESCRIPTION>")
                if remaining <= 0:
                    return ""

                # Truncate description to remaining space
                description = truncate(description, remaining)

                # Insert description
                status = status.replace("<DESCRIPTION>", description or "")

                return status

            except Exception:
                return ""

        case "comment":
            status = status.replace("<VULNID>", event_dict["payload"]["vulnerability"])
            status = status.replace("<TITLE>", event_dict["payload"]["title"])
            status = status.replace("<LINK>", event_dict["uri"])

        case "bundle":
            status = status.replace("<BUNDLETITLE>", event_dict["payload"]["name"])
            status = status.replace("<LINK>", event_dict["uri"])

        case _:
            status = ""

    return status


# ### Streaming functions


def publish(message: str) -> None:
    if message:
        print(message)
        try:
            mastodon.status_post(message)
        except MastodonAPIError as e:
            print(
                f"Mastodon instance returned MastodonAPIError - the server has decided it can't fulfil your request: {str(e)}"
            )
        except Exception as e:
            print(e)


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
        print("Connecting to the event stream…")
        with requests.get(
            url, headers=headers, params=params, stream=True, timeout=None
        ) as response:
            if response.status_code != 200:
                print(f"Error: Received status code {response.status_code}")
                return

            print(f"Connected to the topic '{topic}'. Listening for events…\n")

            for line in response.iter_lines(decode_unicode=True):
                if line.startswith("data:"):
                    # Extract and process the data part
                    data_line = line[5:].strip()
                    try:
                        # Attempt to parse the data as JSON
                        event_data = json.loads(data_line)
                        # print("Received JSON message:")
                        # print(message)
                        publish(create_status_content_sync(event_data, topic))
                    except json.JSONDecodeError:
                        # Handle plain text messages
                        print(f"Received plain message: {data_line}")

    except requests.exceptions.RequestException as req_err:
        print(f"Request error: {req_err}")
        log("error", f"Request error with HTTP event stream: {req_err}")
    except KeyboardInterrupt:
        print("\nStream interrupted by user. Closing connection.")
        log("error", "Stream interrupted by user. Closing connection.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        log("error", f"Unexpected error in listen_to_http_event_stream: {e}")


def listen_to_valkey_stream(topic="comment"):
    """Stream data from the Valkey Pub/Sub service."""
    valkey_client = valkey.Valkey(
        host=config.valkey_host,
        port=config.valkey_port,
        decode_responses=True,
    ).pubsub()
    try:
        valkey_client.subscribe(topic)
    except valkey.exceptions.ConnectionError:
        return
    try:
        while True:
            message = valkey_client.get_message(timeout=10)  # Timeout for listener
            if message and message["type"] == "message":
                # Send entire JSON object as a single `data:` line
                json_message = json.dumps(message["data"])  # Ensure single-line JSON
                yield f"{json_message}"
            heartbeat(process_name=f"process_heartbeat_FediVuln-Publish_{topic}")
    except GeneratorExit:
        valkey_client.unsubscribe(topic)
    except valkey.exceptions.ConnectionError:
        return
    finally:
        valkey_client.close()


def main():
    """Parsing of arguments."""
    parser = argparse.ArgumentParser(prog="FediVuln-Publish")
    parser.add_argument(
        "--valkey",
        dest="valkey",
        action="store_true",
        help="Stream from Valkey instead of streaming for the HTTP event-stream.",
    )
    parser.add_argument(
        "-t",
        "--topic",
        dest="topic",
        default="comment",
        choices=["vulnerability", "comment", "bundle", "sighting"],
        help="The topic to subscribe to.",
    )

    arguments = parser.parse_args()

    if arguments.valkey:
        for elem in listen_to_valkey_stream(topic=arguments.topic):
            event_data = json.loads(elem)
            publish(create_status_content_sync(event_data, arguments.topic))
    else:
        combined = urljoin(config.vulnerability_lookup_base_url, "pubsub/subscribe/")
        full_url = urljoin(combined, arguments.topic)
        headers = {"X-API-KEY": config.vulnerability_auth_token}
        listen_to_http_event_stream(full_url, headers=headers, topic=arguments.topic)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
