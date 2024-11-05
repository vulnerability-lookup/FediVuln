# FediVuln

A client to gather vulnerability-related information from the Fediverse.

## Usage

### Installation

```bash
$ pipx install FediVuln
$ export FEDIVULN_CONFIG=~/.FediVuln/conf.py
```

Set the configuration variables in ``conf.cfg`` as appropriate for your environment.
An [example is provided](fedivuln/conf.cfg-sample).


### Register your application

```bash
$ poetry shell
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


```bash
$ poetry shell
$ FediVuln-Stream --user --sighting
```

Using the ``--sighting`` argument, detected vulnerability IDs will be recorded in
[Vulnerability Lookup](https://github.com/cve-search/vulnerability-lookup) as
[sightings](https://vulnerability-lookup.readthedocs.io/en/latest/sightings.html).


### Publishing

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
