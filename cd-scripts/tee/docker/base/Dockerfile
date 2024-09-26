# tlsnotary base container with init <> notaryserverbuilds.azurecr.io/base/ubuntu23-systemd:latest

FROM            ubuntu:23.10
RUN             apt-get update && apt-get install -y \
                systemd \
                && apt-get clean \
                && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN             rm -f /lib/systemd/system/multi-user.target.wants/*
RUN             rm -rf /etc/update-motd.d/60-unminimize

STOPSIGNAL      SIGRTMIN+3

RUN             systemctl mask systemd-firstboot.service systemd-udevd.service systemd-modules-load.service \
                && systemctl unmask systemd-logind
COPY            container-entrypoint.sh /bin/container-entrypoint.sh

ENTRYPOINT      ["/bin/container-entrypoint.sh"]
