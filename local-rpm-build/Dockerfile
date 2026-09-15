FROM 490606849374.dkr.ecr.us-east-1.amazonaws.com/voice/gcv-base:latest

ENV MAINTAINER=gcv-callp-team@genesys.com

# Install compile dependencies + fpm
RUN dnf update -y && \
    dnf install -y \
    ruby3.2 \
    gcc \
    git \
    make \
    rpm-build \
    ruby-devel \
    which \
    bison \
    flex \
    help2man \
    texinfo \
    libxslt \
    lynx \
    pip \
    ncurses-devel \
    hostname \
    perl-Data-Dumper \
    perl-File-Compare \
    perl-File-Copy && \
    dnf group install -y "Development Tools" && \
    gem install --no-document fpm

# Install library dependencies (matching sipproxy-builds v4_0 group_vars)
RUN dnf install -y \
    postgresql16-devel \
    libcurl-devel \
    libuuid-devel \
    pcre-devel \
    gcv-jsonc-0.13.1-* \
    gcv-openssl-1.1.1w-* \
    gcv-libmicrohttpd-0.9.73-* \
    gcv-dynamodb-sdk-1.11.831-*

COPY ["build-rpm.sh", "/build-rpm.sh"]
RUN chmod +x /build-rpm.sh

VOLUME ["/opensips-src"]
VOLUME ["/target"]

ENTRYPOINT ["/build-rpm.sh"]
