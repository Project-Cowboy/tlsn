# slim tlsnotary server for testing <> x86_64: 14.8MB ;; arm64 26.4MB
### notaryserverbuilds.azurecr.io/base/notary:slim

FROM            rust:alpine3.20 AS zugzug

ARG             TLSN_TAG=dev
ARG             TLSN_FT=default
RUN             apk add --update alpine-sdk xz libressl-dev cmake clang

RUN             git clone --depth 1 -b $TLSN_TAG https://github.com/tlsnotary/tlsn /tlsn && \
                cargo build --release --bin notary-server --features $TLSN_FT --target-dir / --color always --manifest-path /tlsn/Cargo.toml
RUN             wget -q -O- https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-src.tar.xz | tar Jxvf - && \
                cd upx* && make && ./build/release/upx --best -o /notary /release/notary-server

RUN             openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out sk.pem && \
                openssl pkey -in sk.pem -pubout -out pub.pem && \
                openssl req -x509 -new -key sk.pem -days 1 -out self.crt -subj "/CN=tlsnotary.local"

FROM            alpine:edge AS loktar

COPY            --from=zugzug notary .
COPY            --from=zugzug pub.pem .
COPY            --from=zugzug self.crt .
COPY            --from=zugzug sk.pem .
RUN             mkdir /config


RUN             cat <<EOF > /config/config.yaml
server:
  name: "tlsn:slim"
  host: "0.0.0.0"
  port: 7047
  html-info: |
    <blink>{public_key}</blink>
notarization:
  max-sent-data: 16384
  max-recv-data: 16384
tls:
  enabled: false
  private-key-pem-path: "sk.pem"
  certificate-pem-path: "self.crt"

notary-key:
  private-key-pem-path: "sk.pem"
  public-key-pem-path:  "pub.pem"

logging:
  level: ERROR

authorization:
  enabled: false
  whitelist-csv-path: "_.csv"
EOF



ENTRYPOINT      ["/notary"]
