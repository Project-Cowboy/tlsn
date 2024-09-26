#tlsnotary tee development <> qemu + CoCo svsm

FROM ubuntu:24.04

RUN apt update \
    && apt upgrade -y \
    && apt install -y \
        build-essential \
        bzip2 \
        cbindgen \
        curl \
        gcc \
        gettext \
        git \
        iasl \
        libcunit1 \
        libcunit1-dev \
        libcunit1-doc \
        libfdt-dev \
        libglib2.0-dev \
        libpixman-1-dev \
        libslirp-dev \
        libudev-dev \
        libvdeplug-dev \
        make \
        ninja-build \
        python3-venv \
        rustc \
        seabios
        zlib1g-dev \

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && . "$HOME/.cargo/env" \
    && git clone --branch igvm-v0.1.6 https://github.com/microsoft/igvm/ ~/igvm \
    && cd ~/igvm \
    && make -f igvm_c/Makefile \
    && make -f igvm_c/Makefile install

ARG QEMU_DATADIR
RUN git clone https://github.com/coconut-svsm/qemu ~/qemu \
    && cd ~/qemu \
    && git checkout svsm-igvm \
    && export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/lib64/pkgconfig/ \
    && ./configure \
        --datadir=${QEMU_DATADIR} \
        --prefix=$HOME/bin/qemu-svsm/ \
        --target-list=x86_64-softmmu \
        --enable-igvm \
        --static \
        --disable-gio \
        --disable-libudev \
        --enable-kvm \
        --enable-trace-backends=log,simple \
        --enable-slirp \
    && ninja -C build/ \
    && make install -j $(nproc)
