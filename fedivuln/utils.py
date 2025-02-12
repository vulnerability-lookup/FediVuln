import time

import valkey

from fedivuln import config

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
