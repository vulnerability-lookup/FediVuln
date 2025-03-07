import re

# ### Mastodon

# Connection to Mastodon
api_base_url = "https://social.circl.lu"
scopes = ["read", "write", "follow", "push"]
app_name = "Vulnerability-Lookup"
mastodon_clientcred = "mastodon_clientcred.secret"
mastodon_usercred = "mastodon_usercred.secret"

# Optional in case you need to publish status with a different account than the one previously defined:
mastodon_clientcred_push = ""
mastodon_usercred_push = ""

# Templates used when publishing status
templates = {
    "vulnerability": "You can now share your thoughts on vulnerability "
    "<VULNID> in Vulnerability-Lookup:\n<LINK>\n\n<VENDOR> - <PRODUCT>\n\n#VulnerabilityLookup #Vulnerability #Cybersecurity #bot",
    "comment": "Vulnerability <VULNID> has received a comment on "
    "Vulnerability-Lookup:\n\n<TITLE>\n<LINK>\n\n#VulnerabilityLookup #Vulnerability #Cybersecurity #bot",
    "bundle": "A new bundle, <BUNDLETITLE>, has been published "
    "on Vulnerability-Lookup:\n<LINK>\n\n#VulnerabilityLookup #Vulnerability #Cybersecurity #bot",
}

# Regular expression to match CVE, GHSA, and PySec IDs
vulnerability_patterns = re.compile(
    r"\b(CVE-\d{4}-\d{4,})\b"  # CVE pattern
    r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"  # GHSA pattern
    r"|\b(PYSEC-\d{4}-\d{2,5})\b"  # PYSEC pattern
    r"|\b(GSD-\d{4}-\d{4,5})\b"  # GSD pattern
    r"|\b(wid-sec-w-\d{4}-\d{4})\b"  # CERT-Bund pattern
    r"|\b(cisco-sa-\d{8}-[a-zA-Z0-9]+)\b"  # CISCO pattern
    r"|\b(RHSA-\d{4}:\d{4})\b"  # RedHat pattern
    r"|\b(msrc_CVE-\d{4}-\d{4,})\b"  # MSRC CVE pattern
    r"|\b(CERTFR-\d{4}-[A-Z]{3}-\d{3})\b",  # CERT-FR pattern
    re.IGNORECASE,
)


# ### Event stream

# Choice 1: Stream from the authenticated HTTP event stream of Vulnerability-Lookup (default):
vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

# Choice 2: Stream from the Valkey Pub/Sub streaming service (--valkey option):
valkey_host = "127.0.0.1"
valkey_port = 10002


# Hearbeat mechanism
heartbeat_enabled = True
valkey_host = "127.0.0.1"
valkey_port = 10002
expiration_period = 3600
