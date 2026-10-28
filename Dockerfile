# Local image. This repository does not push it to a registry.
# Alpine is musl. The entrypoint downloads the matching v0.1.0 GitHub
# Release archive (x86_64-unknown-linux-musl on x64). There is no
# aarch64 musl build in the release target list.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl jq tar

COPY scripts/fetch-release.sh /usr/local/bin/patchsense
RUN chmod 0755 /usr/local/bin/patchsense

ENTRYPOINT ["/usr/local/bin/patchsense"]
