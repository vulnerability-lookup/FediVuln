import time

import valkey

from fedivuln import config

if config.heartbeat_enabled:
    valkey_client = valkey.Valkey(config.valkey_host, config.valkey_port)


def heartbeat(process_name) -> None:
    """Sends a heartbeat in the Valkey datastore."""
    if not config.heartbeat_enabled:
        return
    try:
        valkey_client.set(process_name, time.time(), ex=config.expiration_period)
    except Exception as e:
        print(f"Heartbeat error: {e}")
        raise  # Propagate the error to stop the process


def log(level="warning", message="", key="process_logs_FediVuln") -> None:
    """Reports an error or warning in the Valkey datastore."""
    timestamp = time.time()
    log_entry = {"timestamp": timestamp, "level": level, "message": message}
    try:
        # Add the log entry to a list, so multiple messages are preserved
        valkey_client.rpush(key, str(log_entry))
        valkey_client.expire(key, 86400)  # Expire after 24 hours
    except Exception as e:
        print(f"Error reporting failure: {e}")
        raise
