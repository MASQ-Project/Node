FROM rust:stretch

ARG uid
ARG gid

RUN (addgroup substratum --gid $gid || continue) \
    && adduser --disabled-password --uid $uid --gid $gid --home /home/substratum substratum \
    && chown -R $uid:$gid /home/substratum

RUN apt-get update && apt-get install -y sudo curl && rustup component add rustfmt clippy \
    && cargo install sccache && chown -R $uid:$gid /usr/local/cargo /usr/local/rustup

USER substratum
