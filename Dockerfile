FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm as ebpf_builder

WORKDIR /app/src
RUN USER=root

RUN apt-get update && apt-get -y install build-essential lsb-release wget perl software-properties-common gnupg pkg-config libssl-dev cmake curl devscripts
RUN mkdir -m 0755 -p /etc/apt/keyrings/ \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /etc/apt/keyrings/llvm-snapshot.gpg.key \
    && echo "deb [signed-by=/etc/apt/keyrings/llvm-snapshot.gpg.key] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main" >> /etc/apt/sources.list \
    && echo "deb-src [signed-by=/etc/apt/keyrings/llvm-snapshot.gpg.key] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main" >> /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y clang-18 lldb-18 lld-18 clangd-18 \
    && mkdir probes

RUN cargo install bpf-linker

COPY bitblazr bitblazr
COPY bitblazr-common bitblazr-common
COPY probes probes
COPY xtask xtask
COPY Cargo.toml Cargo.toml
COPY LICENSE LICENSE
COPY .cargo .cargo

RUN LD_LIBRARY_PATH=/lib/llvm-18/lib/ cargo xtask build-ebpf --release


FROM rust:1-slim-bookworm as builder

WORKDIR /app/src
RUN USER=root

RUN apt-get update && apt-get -y install build-essential lsb-release wget perl software-properties-common gnupg pkg-config libssl-dev cmake

COPY bitblazr bitblazr
COPY bitblazr-common bitblazr-common
COPY config config
COPY xtask xtask
COPY Cargo.toml Cargo.toml
COPY LICENSE LICENSE
COPY .cargo .cargo
COPY run.sh run.sh

RUN cargo build --release

FROM debian:bookworm-slim
LABEL maintainer="info@ziosec.com"
LABEL org.opencontainers.image.source="https://github.com/auseckas/bitblazr"
LABEL usage="docker run -it --privileged --network host -v /custom/config/dir:/app/config -e sensor_name=SENSOR_NAME -e log_level=LOG_LEVEL --name CONTAINER_NAME IMAGE_TAG"

WORKDIR /app
RUN apt-get update \
    && apt-get -y install openssl ca-certificates \
    && mkdir -p /app/probes/target/bpfel-unknown-none/release

COPY --from=builder /app/src/config /app/config
COPY --from=builder /app/src/run.sh /app/run.sh
COPY --from=builder /app/src/LICENSE /app/LICENSE
COPY --from=builder /app/src/target/release/bitblazr /app/bitblazr
COPY --from=ebpf_builder /app/src/probes/target/bpfel-unknown-none/release/bitblazr-lsm /app/probes/target/bpfel-unknown-none/release/bitblazr-lsm
COPY --from=ebpf_builder /app/src/probes/target/bpfel-unknown-none/release/bitblazr-tracepoints /app/probes/target/bpfel-unknown-none/release/bitblazr-tracepoints
RUN chmod 755 /app/run.sh 

VOLUME /app/config

ENV log_level info
ENV sensor_name ""

CMD ["bash", "-c", "/app/run.sh ${log_level} ${sensor_name}"]