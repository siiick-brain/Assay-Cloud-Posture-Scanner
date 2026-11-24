# syntax=docker/dockerfile:1.7
# OpenSCAP scanner with SCAP Security Guide content for Ubuntu 24.04.
# The Ubuntu ssg-debderived package (0.1.71) stops at ubuntu2204, so the
# datastream comes from the upstream ComplianceAsCode release zip instead.

FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289 AS content
ARG SSG_VERSION=0.1.82
# Digest of the release asset as published by GitHub for v0.1.82.
ADD --checksum=sha256:765e84bdce7f9055f9b9c2dd0ee2b713d4255f8eec94eac6d35ea4973c28919c \
    https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip /tmp/ssg.zip
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && mkdir -p /ssg \
    && unzip -o -j /tmp/ssg.zip "*/ssg-ubuntu2404-ds.xml" "*/LICENSE" -d /ssg \
    && rm -rf /var/lib/apt/lists/* /tmp/ssg.zip

FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
ARG OPENSCAP_VERSION=1.3.9+dfsg-1.1ubuntu2
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openscap-scanner=${OPENSCAP_VERSION} \
        openscap-common=${OPENSCAP_VERSION} \
    && rm -rf /var/lib/apt/lists/*
COPY --from=content /ssg/ /usr/share/xml/scap/ssg/content/
COPY scan-root.sh /usr/local/bin/scan-root
RUN chmod 0755 /usr/local/bin/scan-root
WORKDIR /results
ENTRYPOINT ["/usr/local/bin/scan-root"]
