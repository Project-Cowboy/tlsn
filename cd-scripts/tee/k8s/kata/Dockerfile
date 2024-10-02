# kata container base 
## tlsnotary trusted execution environments :: snp - tdx


FROM rust:alpine3.20
FROM golang:1-alpine3.20
COPY --from=0 / /
ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN rustup default nightly
RUN go env && echo $GOBIN && echo $GOPATH
RUN apk add alpine-sdk libclang curl protoc protobuf-dev  bash make git cmake libseccomp-dev libvirt --no-interactive
ARG CODE_DIR=/go/src/github.com/tlsnotary/tlsn
RUN mkdir -p ${CODE_DIR} \
    && git clone\
        -b sc2-main \
        https://github.com/coco-serverless/kata-containers \
        ${CODE_DIR} \
    && git config --global --add safe.directory ${CODE_DIR} \
    && cd ${CODE_DIR}/src/runtime \
    && make \
    && cd ${CODE_DIR}/src/agent \
    && rustup target add x86_64-unknown-linux-musl \
    && make
