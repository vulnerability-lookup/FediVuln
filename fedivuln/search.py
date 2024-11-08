import argparse

from mastodon import Mastodon

from fedivuln import config

mastodon = Mastodon(
    client_id=config.mastodon_clientcred,
    access_token=config.mastodon_usercred,
    api_base_url=config.api_base_url,
)


def main():
    parser = argparse.ArgumentParser(
        prog="FediVuln-Search",
        description="Allows you to search for users, tags and, when enabled, full text, "
        "by default within your own posts and those you have interacted with.",
    )
    parser.add_argument(
        "--query",
        type=str,
        required=True,
        help="Query of the search.",
    )

    arguments = parser.parse_args()
    result = mastodon.search_v2(arguments.query)
    print(result)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
