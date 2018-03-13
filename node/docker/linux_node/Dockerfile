FROM dmouse/browser

ENV SUDO_UID=1000
ENV SUDO_GID=1000

COPY resolv.conf /tmp/resolv.conf
COPY cmd.sh /tmp/cmd.sh

CMD /tmp/cmd.sh
