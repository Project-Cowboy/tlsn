# tlsnotary systemd enabled container <> notarybuildserver.azurecr.io/sgx/dcap:latest
## run out-of-process quotes using the architectural enclave service manager [aesm] : QE / LE / PE
### https://download.01.org/intel-sgx/sgx-dcap/1.10/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

FROM    notaryserverbuilds.azurecr.io/base/ubuntu23-systemd:latest
ENV     REMOVE_SECURETTY="True"
RUN     if [ "$REMOVE_SECURETTY" = "True" ]; then rm -rf /etc/securetty; fi
ENV     DEBIAN_FRONTEND=noninteractive
RUN     \
        apt-get update && apt-get install -y \
        autoconf \
        automake \
        binutils \
        bison \
        build-essential \
        cmake \
        curl \
        debhelper \
        dos2unix \
        gawk \
        gdb \
        git \
        less \
        libboost-dev \
        libboost-system-dev \
        libboost-thread-dev \
        libcurl4-openssl-dev \
        libprotobuf-c-dev \
        libprotobuf-dev \
        libssl-dev \
        libsystemd0 \
        libtool \
        libunwind8 \
        linux-headers-generic \
        locales \
        lsb-release \
        meson \
        nano \
        nasm \
        ninja-build \
        ocaml \
        ocamlbuild \
        openssh-server \
        openssl \
        perl \
        pkg-config \
        pkgconf \
        protobuf-c-compiler \
        protobuf-compiler \
        python-is-python3 \
        python3-click \
        python3-cryptography \
        python3-jinja2 \
        python3-protobuf \
        python3-pyelftools \
        python3-pytest \
        python3-tomli \
        python3-tomli-w \
        python3-voluptuous \
        reprepro \
        strace \
        sudo \
        unzip \
        vim \
        wget \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN     wget https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/distro/ubuntu23.10-server/sgx_linux_x64_sdk_2.24.100.3.bin \
        && chmod +x sgx_linux_x64_sdk_2.24.100.3.bin \
        && ./sgx_linux_x64_sdk_2.24.100.3.bin --prefix /opt/intel
RUN     git clone https://github.com/intel/linux-sgx \
        && cd linux-sgx \
        && make preparation \
        && make psw

#intel pubkey
RUN cat <<EOF > /intel-sgx-deb.key
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGQX9NQBCAC5r7FjjZ8p6nTy2GGyKltSGY6qXxAgZiVV4/kf3/mtcBiboGm6hAaBozNBFnch
Yw2x585L9/cgKzSbaryI02/KF7Hqgqda/szBQDbDXWL0m8kAGrZdMqOZagR3qiguzG07hs8gvKvL
pF4qSrGCLalAZ6ZirpyPaGAH8OtzjYKJEx+zvg2k0f0fNyn3qfoKGOQCTO56AQ6OeUU7I9eqn4mR
9ZmiqW7jDzb5cD9YdaLK0bnloBvB5Cgb6jJSco+JvTAMAGFBEIvPYMCaAoc9adDLglBsxB60Knk6
XzxKY2dulMSkSvObRpmFWesO+BBueYzNpX6ulciCyTuJMYRt8qmVABEBAAG1AClDTj1JbnRlbChS
KSBTb2Z0d2FyZSBEZXZlbG9wbWVudCBQcm9kdWN0c4kBPgQTAQgAKAUCZBf01AIbAwUJB4YfgAYL
CQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ5cfw+hxsbDwDmgf+MjkAdCZAZeGUlxJ5fOqOSGQ4
xot/eGsHEBTkd0IYNzY0yCcigul6RWAingJQh1e5oIl+5S9OB6l64F4mmcKIDld7B9rmO1yt2brN
gzt7Hvf3nLnf7oTT7WNleDvgY2tW48PsEZiuRwnlanjjO4o3wLknBHD7lb1u2rI0978EAvDluWu9
W1W9laRZcsVOgNjtatzcFHjLOt4UYoXOhKlqm0XE6p5NYR1u16DhjHcb8FjpxavOCtq927qgtDvg
GVkM2m7D6hYXCZFnYaINrhbSxSpcyNbHomGEzYTvk0d8q/bS72LgvErP5amQFMileKE14aeZPgm2
zao8yeGaVLHhvA==
=8t8o
-----END PGP PUBLIC KEY BLOCK-----
EOF
RUN     \
        echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu mantic main'     > /etc/apt/sources.list.d/intel-sgx.list \
        && apt-key add /intel-sgx-deb.key
RUN     \
        apt-get update && apt-get install -y \
        libsgx-dcap-quote-verify-dev \
        libsgx-ae-le \
        libsgx-ae-pce \
        libsgx-ae-qe3 \
        libsgx-ae-qve \
        libsgx-aesm-ecdsa-plugin \
        libsgx-aesm-launch-plugin \
        libsgx-aesm-quote-ex-plugin \
        libsgx-dcap-default-qpl \
        libsgx-dcap-ql \
        libsgx-dcap-quote-verify \
        libsgx-dcap-quote-verify-dev \
        libsgx-enclave-common \
        libsgx-launch \
        libsgx-pce-logic \
        libsgx-qe3-logic \
        libsgx-quote-ex \
        libsgx-urts \
        sgx-aesm-service
RUN     git clone --depth 1 https://github.com/gramineproject/gramine.git /builder
RUN     cd /builder \
        && git fetch origin master \
        && git checkout master
RUN     mkdir -p /builder/driver/asm \
        && cd /builder/driver/asm \
        && wget --timeout=10 -O sgx.h         https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/arch/x86/include/uapi/asm/sgx.h?h=v5.11 \
        && sha256sum sgx.h | grep -q a34a997ade42b61376b1c5d3d50f839fd28f2253fa047cb9c0e68a1b00477956
RUN     cd /builder \
        && meson setup build/ --prefix="/builder/gramine/"        --buildtype=release        -Ddirect=enabled -Dsgx=enabled        -Ddcap=enabled \
        && ninja -C build \
        && ninja -C build install
RUN     mkdir -p /config \
        && echo root > /config/root_passwd \
        && echo guest > /config/guest_user \
        && echo guest > /config/guest_passwd \
        && echo '/bin/bash' > /config/guest_shell
COPY    sgx_default_qcnl.conf /builder/
COPY    ttyd.x86_64     /bin/ttyd.x86_64
COPY    ttyd.aarch64    /bin/ttyd.aarch64
RUN     ln -s /bin/ttyd.$(uname -m) /bin/ttyd
COPY    startup.service /lib/systemd/system/startup.service
COPY    startup.sh      /bin/startup.sh
COPY    hostname_capture.service        /lib/systemd/system/hostname_capture.service
COPY    ttyd.service    /lib/systemd/system/ttyd.service
RUN     sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
        && sed -ri 's/UsePAM yes/#UsePAM yes/g' /etc/ssh/sshd_config
RUN     ln -s /lib/systemd/system/startup.service /etc/systemd/system/multi-user.target.wants/startup.service \
        && ln -s /lib/systemd/system/ttyd.service /etc/systemd/system/multi-user.target.wants/hostname_capture.service \
        && ln -s /lib/systemd/system/ttyd.service /etc/systemd/system/multi-user.target.wants/ttyd.service

RUN     curl https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init > /tmp/rustup-init \
        && chmod +x /tmp/rustup-init \
        && /tmp/rustup-init -y --no-modify-path --default-toolchain nightly --profile minimal
ENV     PATH=/root/.cargo/bin:$PATH
RUN     git clone -b dev --depth 1 https://github.com/tlsnotary/tlsn \
        && cd tlsn \
        && cargo build --bin notary-server

RUN     systemctl enable startup hostname_capture ttyd ssh

EXPOSE  22
#tty !dev only
EXPOSE  55699
