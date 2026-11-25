## Generic requirements in order to contribute to FediVuln:

* Read the [contribution guide](https://github.com/vulnerability-lookup/FediVuln/blob/main/CONTRIBUTING.md), including the rules on AI-assisted contributions
* One Pull Request per fix/feature/change/...
* Keep the amount of commits per PR as small as possible
* Please make sure `poetry run pre-commit run --all-files` and `poetry run mypy fedivuln` pass
* Keep the sections below, fill them in, and tick the last box yourself: it is your own statement, not your AI tool's


#### What does it do?

If it fixes an existing issue, please use github syntax: `#<IssueID>`


#### How was it tested?

Against which Mastodon and Vulnerability-Lookup instances, with which commands.


#### Questions

- [ ] Does it require a change in the configuration (`conf_sample.py`)?
- [ ] Was a significant part of it generated with an AI tool? (If so, the commits carry a `Co-Authored-By` trailer naming the model.)
- [ ] I have read, understood and tested every change in this pull request, and I can explain it.
