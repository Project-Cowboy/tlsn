#tlsnotary dev nitro envlave bootstrap

FROM        amazonlinux:2
ARG         RUST_VERSION=nightly
ARG         TLSNTAG=dev
ARG         TLSNFEATS=default

RUN \
            yum groupinstall -y "Development Tools" \
            && yum install -y \
            git \
            vim \
            tar \
            gzip \
            openssl-devel \
            wget \
            docker \
            && yum clean all

ENV         PATH=$PATH:/root/.cargo/bin
RUN         amazon-linux-extras install aws-nitro-enclaves-cli -y && \
            yum install aws-nitro-enclaves-cli-devel -y
RUN         curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
             && rustup default ${RUST_VERSION}

RUN         git clone -b $TLSNTAG https://github.com/tlsnotary/tlsn && cd tlsn && cargo build --bin notary-server --release --features $TLSNFEATS


RUN         openssl ecparam -name prime256v1 -genkey -noout -out ca-private.pem && \
            openssl ec -in ca-private.pem -pubout -out ca-public.pem && \
            openssl req -x509 -new -key ca-private.pem -days 365 -out ca.crt -subj "/CN=tlsnotary.local"


RUN         mkdir /enclave && \
            cp /tlsn/target/release/notary-server /enclave && \
            cp -r /tlsn/crates/notary/server/config /enclave && \
            cp -r /tlsn/crates/notary/server/fixture /enclave 


RUN         cat <<EOF > /enclave/Dockerfile
FROM        amazonlinux:2
COPY        . .
ENTRYPOINT  ["/notary-server"]
EOF


COPY        entrypoint.sh .
RUN         chmod +x entrypoint.sh
ENTRYPOINT  ["/entrypoint.sh"]
