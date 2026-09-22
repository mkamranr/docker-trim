FROM rust:1.83

WORKDIR /build

RUN apt-get update && apt-get install -y pkg-config libssl-dev curl

COPY . .

RUN cargo build --release

ENTRYPOINT ["/build/target/release/mytool"]
