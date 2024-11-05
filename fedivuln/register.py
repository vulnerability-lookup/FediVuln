from mastodon import Mastodon

from fedivuln import config


def main():
    # Step 1: Register the application with Mastodon instance, including all necessary scopes
    Mastodon.create_app(
        config.app_name,
        api_base_url=config.api_base_url,
        to_file=config.mastodon_clientcred,
        scopes=config.scopes,
    )

    # Step 2: Instantiate Mastodon client with client credentials
    mastodon = Mastodon(client_id=config.mastodon_clientcred)

    # Step 3: Log in - Generate authorization URL with the exact same scopes
    login_url = mastodon.auth_request_url(
        client_id=config.mastodon_clientcred,
        scopes=config.scopes,  # Match scopes here
        redirect_uris="urn:ietf:wg:oauth:2.0:oob",
    )
    print("Go to this URL to authorize: ", login_url)

    # # Step 4: Once the user authorizes, prompt for the authorization code
    authorization_code = input("Enter the code you got after authorization: ")

    # Step 5: Use the authorization code to retrieve the access token, with the same scopes
    mastodon.log_in(
        code=authorization_code,
        scopes=config.scopes,  # Match scopes here
        to_file=config.mastodon_usercred,
    )

    # Example API call: Fetch the authenticated user's profile
    # user_profile = mastodon.account_verify_credentials()
    # print(f"Authenticated as: {user_profile['username']}")


if __name__ == "__main__":
    # Point of entry in execution mode.
    main()
