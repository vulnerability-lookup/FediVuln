ARG APP_IMAGE=python:3.11-slim
FROM $APP_IMAGE AS builder

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  PATH="/root/.local/bin:$PATH"

RUN apt-get update && apt-get -y install python3-pip && pip install pipx

FROM $APP_IMAGE
ARG UID=1000
ARG GID=1000

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  PATH="/root/.local/bin:$PATH"

# create basicuser for container and use the GID/UID from the host build user (if provided)
RUN groupadd -g $GID basicuser && useradd -r -u $UID -g basicuser basicuser

RUN mkdir -p /home/basicuser && chown basicuser:basicuser -R /home/basicuser

USER basicuser

WORKDIR "/home/basicuser"

COPY mastodon_clientcred.secret .
COPY mastodon_usercred.secret .

ENV PATH="/home/basicuser/.local/bin:${PATH}"

# Copy dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

RUN pipx install FediVuln

ENTRYPOINT ["FediVuln-Stream", "--public", "--push-sighting"]
