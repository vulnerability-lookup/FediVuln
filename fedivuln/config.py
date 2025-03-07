#! /usr/bin/env python

"""This module is responsible for loading the configuration variables."""

import importlib.util
import os


def load_config(path):
    spec = importlib.util.spec_from_file_location("config", path)
    if spec:
        config = importlib.util.module_from_spec(spec)
        if spec.loader:
            spec.loader.exec_module(config)
    return config


conf = None
try:
    conf = load_config(os.environ.get("FEDIVULN_CONFIG", "fedivuln/conf_sample.py"))
except Exception as exc:
    raise Exception("No configuration file provided.") from exc
finally:
    if not conf:
        raise Exception("No configuration file provided.")

try:
    # For Mastodon
    api_base_url = conf.api_base_url
    scopes = conf.scopes
    app_name = conf.app_name
    mastodon_clientcred = conf.mastodon_clientcred
    mastodon_usercred = conf.mastodon_usercred
    templates = conf.templates

    vulnerability_patterns = conf.vulnerability_patterns

    # For PyVulnerabilityLookup
    vulnerability_lookup_base_url = conf.vulnerability_lookup_base_url
    vulnerability_auth_token = conf.vulnerability_auth_token
except AttributeError:
    raise Exception("Missing configuration variable.")


try:
    # Optional second Mastodon account to publish status
    mastodon_clientcred_push = conf.mastodon_clientcred_push
    mastodon_usercred_push = conf.mastodon_usercred_push

    valkey_host = conf.valkey_host
    valkey_port = conf.valkey_port
except AttributeError:
    mastodon_clientcred_push = ""
    mastodon_usercred_push = ""


try:
    heartbeat_enabled = True
    valkey_host = conf.valkey_host
    valkey_port = conf.valkey_port
    expiration_period = conf.expiration_period
except Exception:
    heartbeat_enabled = False
