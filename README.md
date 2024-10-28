# FediVuln

A client to gather vulnerability-related information from the Fediverse.

## Usage

### Configuration

```bash
$ cp config.py.sample config.py
```

Set the configuration variables in config.py as appropriate for your environment:

- Mastodon instance URL.
- Vulnerability Lookup API root and authentication token.


### Register your application

```bash
$ python register.py
```

This script uses OAuth in order to retrieve the access token. This is achieved in several steps.

- Register the application with Mastodon instance, a including all necessary scopes
- Instantiate Mastodon client with client credentials
- Log in - Generate authorization URL with the exact same scopes
- Once the user authorizes, prompt for the authorization code
- Use the authorization code to retrieve the access token, with the same scopes

You only have to execute it once.


## Streaming


```bash
$ python stream.py
```


## Publishing

```bash
$ python publish.py
```