import argparse

from mastodon import Mastodon

from fedivuln import config

# Set up your Mastodon instance with access credentials
mastodon = Mastodon(
    client_id=config.mastodon_clientcred,
    access_token=config.mastodon_usercred,
    api_base_url=config.api_base_url,
)


def publish(message):
    mastodon.status_post(message)


def main():
    parser = argparse.ArgumentParser(prog="FediVuln-Publish")
    parser.add_argument(
        "-i",
        "--input",
        dest="message",
        required=True,
        help="Message to post.",
    )

    arguments = parser.parse_args()

    publish(arguments.message)


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
