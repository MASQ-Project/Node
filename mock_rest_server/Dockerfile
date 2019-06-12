# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

FROM rustlang/rust:nightly

ENV ROCKET_PORT 80

ADD . /rocket/

RUN cd /rocket/ && cargo build --release

CMD /rocket/target/release/mock_rest_server
