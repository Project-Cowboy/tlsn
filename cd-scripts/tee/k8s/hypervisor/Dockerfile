FROM ubuntu:24.04
# qemu-kvm hypervisor -- tlsnotary testing
## amd64 only, no support for arm64
### tdx -> https://github.com/intel-staging/qemu-tdx/tree/tdx-qemu-wip
### snp -> https://github.com/confidential-containers/qemu.git tag: "amd-snp-202402240000"

RUN ARCH="${3:-$(uname -m)}"

RUN apt update \
    && apt upgrade -y \
    && apt install -y \
    bzip2 \
    g++ \
    gcc \
    git \
    libaio-dev \
    libblkid-dev \
    libcap-ng-dev \
    libdw-dev \
    libelf-dev \
    libffi-dev \
    libglib2.0-dev \
    libjson-c-dev \
    libltdl-dev \
    libmount-dev \
    libpixman-1-dev \
    libpmem-dev \
    libpopt-dev \
    libseccomp-dev \
    libseccomp2 \
    libselinux1-dev \
    libssl-dev \
    libtool \
    make \
    ninja-build \
    pkg-config \
    python3 \
    python3-venv \
    uuid-dev \
    wget \
    zlib1g-dev 

ARG QEMU_DATADIR=/opt/firmware
RUN mkdir -p /usr/src \
    && git clone \
        -b v8.2.4 \
        --single-branch --depth 1 \
        https://gitlab.com/qemu-project/qemu.git \
        /usr/src/qemu \
    && cd /usr/src/qemu \
    && ./configure \
    --cpu=x86_64 \
    --datadir=${QEMU_DATADIR} \
    --disable-auth-pam \
    --disable-avx512bw \
    --disable-bochs \
    --disable-bsd-user \
    --disable-capstone \
    --disable-cloop \
    --disable-colo-proxy \
    --disable-curl \
    --disable-curses \
    --disable-debug-graph-lock \
    --disable-dmg \
    --disable-docs \
    --disable-gio \
    --disable-glusterfs \
    --disable-gtk \
    --disable-guest-agent \
    --disable-guest-agent-msi \
    --disable-hexagon-idef-parser \
    --disable-hv-balloon \
    --disable-libdw \
    --disable-libiscsi \
    --disable-libudev \
    --disable-linux-user \
    --disable-live-block-migration \
    --disable-lzo \
    --disable-opengl \
    --disable-parallels \
    --disable-pipewire \
    --disable-pixman \
    --disable-qcow1 \
    --disable-qed \
    --disable-rdma \
    --disable-relocatable \
    --disable-replication \
    --disable-rutabaga-gfx \
    --disable-sdl \
    --disable-snappy \
    --disable-spice \
    --disable-tools \
    --disable-tpm \
    --disable-vde \
    --disable-vdi \
    --disable-vhdx \
    --disable-virglrenderer \
    --disable-vmdk \
    --disable-vnc \
    --disable-vnc-jpeg \
    --disable-vnc-sasl \
    --disable-vpc \
    --disable-vte \
    --disable-vvfat \
    --disable-xen \
    --enable-attr \
    --enable-avx2 \
    --enable-avx512f \
    --enable-cap-ng \
    --enable-kvm \
    --enable-libpmem \
    --enable-linux-aio \
    --enable-malloc-trim \
    --enable-seccomp \
    --enable-trace-backends=log,simple \
    --enable-virtfs \
    --static \
    --target-list=x86_64-softmmu \
    && make -j $(nproc)

WORKDIR /usr/src/qemu
