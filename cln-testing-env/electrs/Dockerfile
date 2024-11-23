FROM debian:bookworm-slim AS base
RUN apt-get update -qqy
RUN apt-get install -qqy librocksdb-dev curl

### Electrum Rust Server ###
FROM base AS electrs-build
RUN apt-get install -qqy cargo clang cmake git

# Install electrs
WORKDIR /build
RUN git clone https://github.com/romanz/electrs
WORKDIR /build/electrs
ENV ROCKSDB_INCLUDE_DIR=/usr/include
ENV ROCKSDB_LIB_DIR=/usr/lib
RUN cargo install --locked --path .

FROM base AS result
# Copy the binaries
COPY --from=electrs-build /root/.cargo/bin/electrs /usr/bin/electrs

WORKDIR /

# Expose the electrs port
EXPOSE 60601

# Run electrs
#ENTRYPOINT ["tail", "-f"]
ENTRYPOINT ["electrs", "--conf", "/electrs.toml"]