def get_vendor_product_cve(data):
    return [
        (entry["vendor"], entry["product"])
        for entry in data["containers"]["cna"]["affected"]
    ]


def truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 1].rstrip() + "…"
