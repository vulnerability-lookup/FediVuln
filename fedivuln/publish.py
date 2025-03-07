import argparse
import json
from urllib.parse import urljoin

import requests
import valkey
from mastodon import Mastodon

from fedivuln import config
from fedivuln.monitoring import heartbeat, log
from fedivuln.utils import get_vendor_product_cve

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


def create_status_content(event_data: str, topic: str) -> str:
    """Generates a status update for posting based on the monitored topic."""
    event_dict = json.loads(event_data)
    status = config.templates.get(topic, "")
    match topic:
        case "vulnerability":
            # CVE
            try:
                if (
                    event_dict["cveMetadata"]["datePublished"]
                    != event_dict["cveMetadata"]["dateUpdated"]
                ):
                    return ""
                vendor, product = get_vendor_product_cve(event_dict)[0]
                status = status.replace("<VULNID>", event_dict["cveMetadata"]["cveId"])
                status = status.replace(
                    "<LINK>",
                    f"https://vulnerability.circl.lu/vuln/{event_dict['cveMetadata']['cveId']}",
                )
                status = status.replace("<VENDOR>", vendor)
                status = status.replace("<PRODUCT>", product)
                return status
            except Exception:
                pass

            # GHSA, PySec
            try:
                if event_dict["published"] != event_dict["modified"]:
                    return ""
                status = status.replace("<VULNID>", event_dict["id"])
                status = status.replace(
                    "<LINK>", f"https://vulnerability.circl.lu/vuln/{event_dict['id']}"
                )
                status = status.replace("<VENDOR>", "")
                status = status.replace("<PRODUCT>", "")
                return status
            except Exception:
                pass

            # CSAF
            try:
                if (
                    event_dict["document"]["tracking"]["initial_release_date"]
                    != event_dict["document"]["tracking"]["current_release_date"]
                ):
                    return ""
                try:
                    vuln_id = event_dict["document"]["tracking"]["id"].replace(":", "_")
                except Exception:
                    vuln_id = event_dict["document"]["tracking"]["id"]
                status = status.replace("<VULNID>", vuln_id)
                status = status.replace(
                    "<LINK>", f"https://vulnerability.circl.lu/vuln/{vuln_id}"
                )
                status = status.replace("<VENDOR>", "")
                status = status.replace("<PRODUCT>", "")
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
                        publish(create_status_content(event_data, topic))
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
            publish(create_status_content(event_data, arguments.topic))
    else:
        combined = urljoin(config.vulnerability_lookup_base_url, "pubsub/subscribe/")
        full_url = urljoin(combined, arguments.topic)
        headers = {"X-API-KEY": config.vulnerability_auth_token}
        listen_to_http_event_stream(full_url, headers=headers, topic=arguments.topic)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
