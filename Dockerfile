
ARG GOLANG_IMAGE_HASH=b274ff14d8eb9309b61b1a45333bf0559a554ebcf6732fa2012dbed9b01ea56f
ARG NOTARYTLS_IMAGE_HASH=9bfa5fe65a611e75e6f81059890feb9c449ac068e33a8b4f75c0f2544fa5e6b1
ARG REPROXY_IMAGE_HASH=4508857394a6cb727e6f23f3d1986067847d5ea0753646acc6d2908f8cd14af1
ARG BASE_IMAGE_HASH=58b87898e82351c6cf9cf5b9f3c20257bb9e2dcf33af051e12ce532d7f94e3fe

FROM golang:1.22@sha256:${GOLANG_IMAGE_HASH} as nitridin-builder

# 1.4.2
ARG NITRIDING_COMMIT_HASH=efde3854070055d2a632e3c7bbf231f89ac09656

WORKDIR /build
RUN git clone https://github.com/brave/nitriding-daemon.git
RUN cd nitriding-daemon && \
    git checkout $NITRIDING_COMMIT_HASH && \
    echo "git branch: $(git branch)" && \
    echo "git log: $(git log -1)" && \
    echo "COMMIT_HASH $NITRIDING_COMMIT_HASH" && \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-buildid= -s -w" -buildvcs=false -o /build/nitriding

FROM ubuntu:22.04 as multirun

RUN apt-get update && apt-get install -y wget tar
RUN FNAME=multirun-x86_64-linux-gnu-1.1.3.tar.gz && \
    wget https://github.com/nicolas-van/multirun/releases/download/1.1.3/$FNAME && \
    tar -xvf $FNAME && \
    mv multirun /usr/local/bin/multirun


FROM umputun/reproxy@sha256:${REPROXY_IMAGE_HASH} as reproxy

FROM golang:1.22@sha256:${GOLANG_IMAGE_HASH} as app-builder

WORKDIR /app
COPY app .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-buildid= -s -w" -buildvcs=false -o main

FROM ubuntu:22.04@sha256:${BASE_IMAGE_HASH} as certs

RUN apt-get update && apt-get install -y ca-certificates=20240203~22.04.1

FROM ubuntu:22.04@sha256:${BASE_IMAGE_HASH}

# Install repoxy
COPY --from=reproxy /srv/reproxy /usr/local/bin/reproxy

# Install multirun
COPY --from=multirun /usr/local/bin/multirun /usr/local/bin/multirun

# Install nitriding
COPY --from=nitridin-builder /build/nitriding /usr/local/bin/nitriding

# Install certificates
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

# Install app
COPY --from=app-builder /app/main /app/main

# Copy all from bin
COPY bin /usr/local/bin

COPY entrypoint.sh /entrypoint.sh
COPY launch.sh /launch.sh

ENTRYPOINT [ "/entrypoint.sh" ]