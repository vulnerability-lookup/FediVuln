import argparse
import asyncio
import json
import sys
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import getproxies, proxy_bypass

import aiohttp
from mastodon import (
    Mastodon,
    MastodonAPIError,
    MastodonError,
    MastodonMalformedEventError,
    MastodonNetworkError,
    StreamListener,
)
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
                    status["uri"],
                    vulnerability_ids,
                    content=content if config.push_sighting_content else None,
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


def push_sighting_to_vulnerability_lookup(status_uri, vulnerability_ids, content=None):
    """Create a sighting from an incoming status and push it to the Vulnerability-Lookup instance."""
    print("Pushing sighting to Vulnerability-Lookup…")
    vuln_lookup = PyVulnerabilityLookup(
        config.vulnerability_lookup_base_url, token=config.vulnerability_auth_token
    )
    for vuln in vulnerability_ids:
        # Create the sighting
        sighting = {"type": "seen", "source": status_uri, "vulnerability": vuln}
        if content:
            sighting["content"] = content

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


def streaming_websocket_url(stream: str) -> str:
    """URL of the instance's WebSocket streaming endpoint for ``stream``."""
    base = None
    # v2 instance info, then v1, then assume the API host also streams. A
    # failed lookup (missing field, HTTP error, timeout) just moves on: if the
    # instance is really down, connecting to the socket fails and is reported.
    not_available = (MastodonError, KeyError, TypeError, AttributeError)
    try:
        base = mastodon.instance()["configuration"]["urls"]["streaming"]
    except not_available as err:
        print(f"Streaming URL not in instance info: {err!r}")
    if not base:
        try:
            base = mastodon.instance_v1()["urls"]["streaming_api"]
        except not_available as err:
            print(f"Streaming URL not in v1 instance info: {err!r}")
    if not base:
        # Typed Optional, but always set: the client is built with a base URL.
        base = (
            (mastodon.api_base_url or "")
            .replace("https://", "wss://", 1)
            .replace("http://", "ws://", 1)
        )
    return f"{base.rstrip('/')}/api/v1/streaming?stream={stream}"


def proxy_for_websocket(url: str):
    """Proxy from the environment for a ws(s) URL.

    aiohttp's trust_env looks up proxies by the URL's own scheme, so a wss://
    URL would need a WSS_PROXY variable. Use the https/http proxy instead,
    like the HTTP client does, and honour no_proxy.
    """
    parsed = urlparse(url)
    if proxy_bypass(parsed.hostname or ""):
        return None
    return getproxies().get("https" if parsed.scheme == "wss" else "http")


def websocket_frame_to_event(data: str) -> dict:
    """Turn a WebSocket text frame into the event dict ``_dispatch`` expects.

    Raises MastodonAPIError for an ``{"error": ...}`` frame, which the server
    sends e.g. for a rejected token or subscription, and
    MastodonMalformedEventError for anything else that is not an event.
    """
    try:
        frame = json.loads(data)
    except ValueError as err:
        raise MastodonMalformedEventError("Bad JSON", data) from err
    if not isinstance(frame, dict):
        raise MastodonMalformedEventError("Not an event", data)
    if "error" in frame:
        raise MastodonAPIError(f"Streaming server error: {frame['error']}")
    if "event" not in frame:
        raise MastodonMalformedEventError("Missing field", "event", frame)
    payload = frame.get("payload", "null")
    if not isinstance(payload, str):
        # Mastodon sends the payload as a JSON string; some servers send the
        # object itself. _dispatch expects the string form.
        payload = json.dumps(payload)
    return {
        "event": frame["event"],
        "data": payload,
        "stream": json.dumps(frame.get("stream")),
    }


def stream_websocket(listener: StreamListener, stream: str = "user") -> None:
    """Stream events over the WebSocket API and hand them to ``listener``.

    Mastodon.py streams over a long-lived HTTP/1.1 response. Some servers
    buffer those responses, so nothing arrives until the buffer has filled: a
    quiet home timeline then never gets through the read timeout and the
    stream keeps reconnecting. The WebSocket endpoint, which the web and
    mobile clients use, is not buffered. Events are dispatched through the
    same path Mastodon.py uses, so the listener callbacks behave identically.
    Returns only by raising, like Mastodon.py's stream_* methods.

    Reading and dispatching run as separate tasks joined by a queue. The
    listener callbacks block (sighting pushes, Valkey calls), so they run in a
    worker thread while the reader keeps calling ``ws.receive()``: pings are
    answered and pongs seen however long a callback takes.
    """
    url = streaming_websocket_url(stream)
    headers = {}
    if mastodon.access_token:
        headers["Authorization"] = f"Bearer {mastodon.access_token}"

    proxy = proxy_for_websocket(url)

    # Queue items: an event dict to dispatch, IDLE for a quiet minute, or the
    # MastodonError that ends the stream (queued after the events before it).
    IDLE = None
    # Events waiting for the dispatcher. Past this, Vulnerability-Lookup is not
    # keeping up: stop reading and end the stream rather than buffer without
    # bound. (Blocking on a full queue would leave pings unanswered again.)
    MAX_BACKLOG = 1000

    async def read_frames(
        ws: aiohttp.ClientWebSocketResponse, queue: asyncio.Queue
    ) -> None:
        try:
            while True:
                try:
                    msg = await ws.receive(timeout=60)
                except asyncio.TimeoutError:
                    # Quiet minute; the ping/pong heartbeat has kept the
                    # socket checked, so the process is alive and idle.
                    queue.put_nowait(IDLE)
                    continue
                if msg.type == aiohttp.WSMsgType.TEXT:
                    if queue.qsize() >= MAX_BACKLOG:
                        raise MastodonNetworkError(
                            f"Event backlog exceeded {MAX_BACKLOG}: dispatch is not keeping up."
                        )
                    queue.put_nowait(websocket_frame_to_event(msg.data))
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    # msg.data is the exception, e.g. a pong timeout.
                    raise MastodonNetworkError(
                        f"WebSocket error: {msg.data!r}"
                    ) from msg.data
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    reason = f" ({msg.extra})" if msg.extra else ""
                    raise MastodonNetworkError(
                        "Server ceased communication: "
                        f"close code {ws.close_code}{reason}."
                    )
        except MastodonError as err:
            queue.put_nowait(err)
        except aiohttp.ClientError as err:
            queue.put_nowait(
                MastodonNetworkError(f"WebSocket connection failed: {err}")
            )

    async def dispatch_events(queue: asyncio.Queue) -> None:
        while True:
            item = await queue.get()
            if isinstance(item, MastodonError):
                listener.on_abort(item)
                raise item
            if item is not IDLE:
                # _dispatch reports malformed events through on_abort itself.
                await asyncio.to_thread(listener._dispatch, item)
            await asyncio.to_thread(listener.handle_heartbeat)

    async def run() -> None:
        queue: asyncio.Queue = asyncio.Queue()
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(
                url, headers=headers, heartbeat=30, proxy=proxy
            ) as ws:
                reader = asyncio.create_task(read_frames(ws, queue))
                try:
                    await dispatch_events(queue)
                finally:
                    reader.cancel()

    try:
        asyncio.run(run())
    except aiohttp.ClientError as err:
        # Failed to connect: the reader never started.
        exception = MastodonNetworkError(f"WebSocket connection failed: {err}")
        listener.on_abort(exception)
        raise exception from err


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
    parser.add_argument(
        "--websocket",
        action="store_true",
        help="Use the WebSocket streaming API instead of HTTP streaming. "
        "Needed when the server buffers HTTP streaming responses, which delays or starves the stream.",
    )
    # parser.add_argument(
    #     "--push-status",
    #     action="store_true",
    #     help="Push the status to Vulnerability-Lookup.",
    # )

    arguments = parser.parse_args()

    # Instantiate the listener
    listener = VulnStreamListener(push_sighting=arguments.push_sighting)

    if arguments.websocket and (arguments.user or arguments.public):
        stream = "user" if arguments.user else "public"
        print(f"Starting Mastodon {stream} stream over WebSocket…")
        stream_websocket(listener, stream)
    elif arguments.user:
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
