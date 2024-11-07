# FediVuln

A client to gather vulnerability-related information from the Fediverse.

## Usage

### Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install FediVuln
$ export FEDIVULN_CONFIG=~/.FediVuln/conf.py
```

The configuration for FediVuln should be defined in a Python file (e.g., ``~/.FediVuln/conf.py``).
You must then set an environment variable (``FEDIVULN_CONFIG``) with the full path to this file.

You can have a look at [this example](https://github.com/CIRCL/FediVuln/blob/main/fedivuln/conf_sample.py) of configuration.


### Register your application

```bash
$ FediVuln-Register
```

This script uses OAuth in order to retrieve the access token. This is achieved in several steps.

- Register the application with Mastodon instance, a including all necessary scopes
- Instantiate Mastodon client with client credentials
- Log in - Generate authorization URL with the exact same scopes
- Once the user authorizes, prompt for the authorization code
- Use the authorization code to retrieve the access token, with the same scopes

You only have to execute it once.


### Streaming

Streams events that are relevant to the authorized user, i.e. home timeline and notifications:

```bash
$ FediVuln-Stream --user --push-sighting
```

If you want to get the stream of public events (local server + connected servers):

```bash
$ FediVuln-Stream --public --push-sighting
```


Using the ``--push-sighting`` argument, detected vulnerability IDs will be recorded in
[Vulnerability Lookup](https://github.com/cve-search/vulnerability-lookup) as
[sightings](https://vulnerability-lookup.readthedocs.io/en/latest/sightings.html).

With ``--push-status`` argument, the full JSON status object will be sent to the
Vulnerability Lookup instance and stored in the kvrocks database.


### Publishing

WIP.

```bash
$ python publish.py
```


## License

[FediVuln](https://github.com/CIRCL/FediVuln) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2024 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2024 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
