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
    "<VULNID> in Vulnerability-Lookup:\n<LINK>\n\n#VulnerabilityLookup #Vulnerability #Cybersecurity #bot",
    "comment": "Vulnerability <VULNID> has received a comment on "
    "Vulnerability-Lookup:\n\n<TITLE>\n<LINK>\n\n#VulnerabilityLookup #Vulnerability #Cybersecurity #bot",
    "bundle": "A new bundle, <BUNDLETITLE>, has been published "
    "on Vulnerability-Lookup:\n<LINK>\n\n#VulnerabilityLookup #Vulnerability #Cybersecurity #bot",
}


# ### Event stream

# Choice 1: Stream from the authenticated HTTP event stream of Vulnerability-Lookup (default):
vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

# Choice 2: Stream from the Valkey Pub/Sub streaming service (--valkey option):
valkey_host = "127.0.0.1"
valkey_port = 10002
