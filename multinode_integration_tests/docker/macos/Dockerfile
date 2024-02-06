FROM rust:bullseye

ARG uid
ARG gid

RUN (addgroup masq --gid $gid || continue) \
    && adduser --disabled-password --uid $uid --gid $gid --home /home/masq masq \
    && chown -R $uid:$gid /home/masq

RUN apt-get update && apt-get install -y sudo curl && rustup component add rustfmt clippy \
    && cargo install sccache && chown -R $uid:$gid /usr/local/cargo /usr/local/rustup

USER masq
