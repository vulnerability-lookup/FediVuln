# FediVuln

A client to gather vulnerability-related information from the Fediverse.

## Usage

### Configuration

```bash
$ poetry install
$ poetry shell
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
$ FediVuln-Stream --user
```


## Publishing

```bash
$ python publish.py
```


## License

This software is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2024 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2024 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
