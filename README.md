<div align="center">

# FediVuln

**Connects the Fediverse and Vulnerability-Lookup: collects vulnerability sightings from Mastodon and publishes Vulnerability-Lookup activity back.**

[![Latest release](https://img.shields.io/github/release/vulnerability-lookup/FediVuln.svg?style=flat-square)](https://github.com/vulnerability-lookup/FediVuln/releases/latest)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Contributors](https://img.shields.io/github/contributors/vulnerability-lookup/FediVuln.svg?style=flat-square)](https://github.com/vulnerability-lookup/FediVuln/graphs/contributors)
[![Stars](https://img.shields.io/github/stars/vulnerability-lookup/FediVuln.svg?style=flat-square)](https://github.com/vulnerability-lookup/FediVuln/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/vulnerability-lookup/FediVuln.svg?style=flat-square)](https://github.com/vulnerability-lookup/FediVuln/commits/main)

[![AI use](https://www.saywhichai.org/badge/fedivuln.svg)](https://www.saywhichai.org/?project=fedivuln)

</div>

FediVuln is a Mastodon client that links the Fediverse with a
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup)
instance, in both directions:

- **From the Fediverse:** ``FediVuln-Stream`` follows Mastodon streams, detects
  vulnerability identifiers (CVE, GHSA, PYSEC, CERT-FR and more) in statuses,
  and records each one in Vulnerability-Lookup as a
  [sighting](https://www.vulnerability-lookup.org/documentation/sightings.html).
- **To the Fediverse:** ``FediVuln-Publish`` subscribes to the event stream of
  Vulnerability-Lookup and posts new vulnerabilities, comments, bundles and
  sightings on Mastodon.


## Installation

The simplest way to install FediVuln is with [pipx](https://github.com/pypa/pipx)
([installation instructions](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux)),
which runs Python applications in isolated environments:

```bash
$ pipx install FediVuln
$ export FEDIVULN_CONFIG=~/.FediVuln/conf.py
```

FediVuln is configured with a Python file, such as ``~/.FediVuln/conf.py``.
Set the ``FEDIVULN_CONFIG`` environment variable to the full path of this file.
Start from the [sample configuration](https://github.com/vulnerability-lookup/FediVuln/blob/main/fedivuln/conf_sample.py).


### With Docker

```bash
git clone https://github.com/vulnerability-lookup/FediVuln
cd FediVuln

# Create fedivuln/conf.py before running (see the note below)
docker compose up --build
```

> [!NOTE]
> ``docker-compose.yml`` mounts ``fedivuln/conf.py`` into the container as its configuration.
> Create it from the sample configuration:
>
> ```bash
> $ cp fedivuln/conf_sample.py fedivuln/conf.py
> ```

By default, the container runs ``FediVuln-Stream --public --push-sighting``. To
pass other arguments, for example ``--websocket``, set ``command:`` in
``docker-compose.yml`` (a commented example is included) or append them to
``docker run <image>``.


## Usage

### Register your application

```bash
$ FediVuln-Register
```

This script retrieves an access token through OAuth, in the following steps:

- Register the application with the Mastodon instance, including all the necessary scopes.
- Create a Mastodon client with the client credentials.
- Generate an authorization URL with exactly the same scopes, and open it to log in.
- Once you have authorized the application, enter the authorization code.
- Exchange the authorization code for an access token, with the same scopes.

You only need to run it once.


### Streaming

``FediVuln-Stream`` streams statuses from the Fediverse and uses
[PyVulnerabilityLookup](https://github.com/vulnerability-lookup/PyVulnerabilityLookup)
to create sightings in Vulnerability-Lookup.

```bash
usage: FediVuln-Stream [-h] [--user] [--public] [--push-sighting] [--websocket]

Allows access to the streaming API.

options:
  -h, --help       show this help message and exit
  --user           Streams events that are relevant to the authorized user, i.e. home timeline and notifications.
  --public         Streams public events.
  --push-sighting  Push the sightings to Vulnerability-Lookup.
  --websocket      Use the WebSocket streaming API instead of HTTP streaming. Needed when the server buffers
                   HTTP streaming responses, which delays or starves the stream.
```

#### Examples

Stream the events relevant to the authorized user (home timeline and notifications):

```bash
$ FediVuln-Stream --user --push-sighting
```

Stream public events (from the local server and the servers it is connected to):

```bash
$ FediVuln-Stream --public --push-sighting
```

If the stream connects but no events arrive, or connecting times out although
the instance is up, the server is probably buffering HTTP streaming responses:
it sends nothing until its buffer is full, which a quiet home timeline never
fills. Add ``--websocket`` to subscribe over the WebSocket endpoint instead,
which is not affected:

```bash
$ FediVuln-Stream --user --push-sighting --websocket
```

With ``--push-sighting``, each detected vulnerability ID is recorded in
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) as a
[sighting](https://www.vulnerability-lookup.org/documentation/sightings.html).


### Publishing

``FediVuln-Publish`` subscribes to the event stream of Vulnerability-Lookup, over
HTTP or through Valkey, and publishes the incoming events on the Fediverse.

```bash
$ FediVuln-Publish --help
usage: FediVuln-Publish [-h] [--valkey]
                        [-t {vulnerability,comment,bundle,sighting}]

options:
  -h, --help            show this help message and exit
  --valkey              Stream from Valkey instead of streaming for the HTTP
                        event-stream.
  -t, --topic {vulnerability,comment,bundle,sighting}
                        The topic to subscribe to.
```

PyVulnerabilityLookup handles the authentication to the HTTP event stream.

For each incoming event, FediVuln posts a status with the configured Mastodon
account, formatted for the event's topic. For example, ``FediVuln-Publish -t comment``
picks up every new comment and posts a readable summary on the Fediverse, with a
link to the original comment on the Vulnerability-Lookup instance.


### Search

``FediVuln-Search`` searches the Mastodon instance with the configured account.

```bash
$ FediVuln-Search --help
usage: FediVuln-Search [-h] --query QUERY

Allows you to search for users, tags and, when enabled, full text, by default within your own posts and those you have interacted with.

options:
  -h, --help     show this help message and exit
  --query QUERY  Query of the search.
```


## License

[FediVuln](https://github.com/vulnerability-lookup/FediVuln) is licensed under the
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)
or later.

~~~
Copyright (c) 2024-2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2024-2026 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
