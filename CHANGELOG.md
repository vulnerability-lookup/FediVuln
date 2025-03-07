# Changelog

## Release 1.1.2 (2025-03-07)

Fixed an issue which caused the publication of a lot of useless posts.


## Release 1.1.1 (2025-03-07)

Only publish notifications about new vulnerabilities from CVE advisories.


## Release 1.1.0 (2025-03-07)

Improvements to the publish module for the notifications about new vulnerabilities
on Mastodon.


## Release 1.0.0 (2025-02-13)

This release introduces the capability to report errors, warnings,
and heartbeats to a Valkey datastore, facilitating centralized monitoring.


## Release 0.8.0 (2025-01-23)

Bugfix (stupid bug) and updated dependencies.


## Release 0.7.0 (2025-01-14)

Regular expressions are now defined in the configuration file.


## Release 0.6.2 (2024-12-16)

Directly return the updated status before trying another source of
vulnerabilities. This prevents overriding the content generated in
the previous try block.
