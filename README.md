# FediVuln

A client to gather vulnerability-related information from the Fediverse.
The collected data is then sent to the
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) API as sightings.


## Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install FediVuln
$ export FEDIVULN_CONFIG=~/.FediVuln/conf.py
```

The configuration for FediVuln should be defined in a Python file (e.g., ``~/.FediVuln/conf.py``).
You must then set an environment variable (``FEDIVULN_CONFIG``) with the full path to this file.

You can have a look at [this example](https://github.com/vulnerability-lookup/FediVuln/blob/main/fedivuln/conf_sample.py) of configuration.


## Usage

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

``FediVuln-Stream`` streams data from the Fediverse and uses PyVulnerabilityLookup to create sightings in Vulnerability-Lookup.

```bash
usage: FediVuln-Stream [-h] [--user] [--public] [--push-sighting] [--push-status]

Allows access to the streaming API.

options:
  -h, --help       show this help message and exit
  --user           Streams events that are relevant to the authorized user, i.e. home timeline and notifications.
  --public         Streams public events.
  --push-sighting  Push the sightings to Vulnerability Lookup.
  --push-status    Push the status to Vulnerability Lookup.
```

#### Examples

Streams events that are relevant to the authorized user, i.e. home timeline and notifications:

```bash
$ FediVuln-Stream --user --push-sighting
```

If you want to get the stream of public events (local server + connected servers):

```bash
$ FediVuln-Stream --public --push-sighting
```

Using the ``--push-sighting`` argument, detected vulnerability IDs will be recorded in
[Vulnerability Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) as
[sightings](https://www.vulnerability-lookup.org/documentation/sightings.html).


### Publishing

``FediVuln-Publish`` subscribes to an HTTP or Redis event stream and publishes the incoming data to the Fediverse.

```bash
$ FediVuln-Publish --help
usage: FediVuln-Publish [-h] [-t {vulnerability,comment,bundle,sighting}]

options:
  -h, --help            show this help message and exit
  -t {vulnerability,comment,bundle,sighting}, --topic {vulnerability,comment,bundle,sighting}
                        The topic to subscribe to.
```

The authentication to the HTTP event stream is automatically handled by PyVulnerabilityLookup.

For each incoming event, a status will be posted using the configured Mastodon account.
The format of the status is dynamically tailored to the specific event topic.
For instance, executing the command ``FediVuln-Publish -t comment`` will capture all
new comments and share a human-readable summary on the Fediverse, including a link to the
original comment on the Vulnerability-Lookup instance.



### Search

```bash
$ FediVuln-Search --help
usage: FediVuln-Search [-h] --query QUERY

Allows you to search for users, tags and, when enabled, full text, by default within your own posts and those you have interacted with.

options:
  -h, --help     show this help message and exit
  --query QUERY  Query of the search.
```



## License

[FediVuln](https://github.com/vulnerability-lookup/FediVuln) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2024-2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2024-2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
