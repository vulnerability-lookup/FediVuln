from typing import Any, Dict, Optional

import aiohttp


def get_vendor_product_cve(data):
    return [
        (entry["vendor"], entry["product"])
        for entry in data["containers"]["cna"]["affected"]
    ]


def truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 1].rstrip() + "…"


async def classify_vulnerability_severity(
    description: str,
) -> Optional[Dict[str, Any]]:
    """Classify vulnerability severity from a textual description.

    Returns a dict like:
        {"severity": "High", "confidence": 0.8267}

    Returns None if the request succeeds but no usable result is returned.
    Raises aiohttp.ClientError / asyncio.TimeoutError on errors.
    """
    url = "https://vulnerability.circl.lu/api/vlai/severity-classification"

    payload = {"description": description}

    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }

    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload, headers=headers) as response:
            response.raise_for_status()
            data = await response.json()

    if not isinstance(data, dict):
        return None

    if "severity" in data and "confidence" in data:
        return data

    return None
