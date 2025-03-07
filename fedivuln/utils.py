def get_vendor_product_cve(data):
    return [
        (entry["vendor"], entry["product"])
        for entry in data["containers"]["cna"]["affected"]
    ]
