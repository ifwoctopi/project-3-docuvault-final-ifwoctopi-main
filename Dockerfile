# =======================================================================
# DocuVault — Checkpoint 1 Dockerfile
#
# Complete the TODO sections below so that:
#   1. Your C++ server compiles inside the container during `docker build`.
#   2. The container exposes port 8080.
#   3. `docker run -p 8080:8080 docuvault` starts your server with no
#      additional arguments.
#   4. The block storage directory and user file exist at known paths.
# =======================================================================

# --- Base image (provided — do not change) ---
FROM ubuntu:22.04

# Prevent interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# --- TODO 1: Install build dependencies ---
# Install the packages your server needs to compile and run.
# At minimum you will need: g++, make (optional), and libssl-dev
# (for OpenSSL's SHA-256 functions).
#
# Example:
#   RUN apt-get update && apt-get install -y <packages> && \
#       rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y g++ libssl-dev && \
    rm -rf /var/lib/apt/lists/*


# --- Set up working directory (provided — do not change) ---
WORKDIR /app

# --- Copy source code into the image ---
COPY src/ src/
COPY data/ /data/

# --- TODO 2: Compile your server ---
# Write the g++ command to compile all .cpp files in src/ into a
# single binary.  You must link against the OpenSSL crypto library
# and the pthreads library.
#
# Suggested compile command:
#   g++ -std=c++17 -O2 -o docuvault_server \
#       src/server.cpp src/auth.cpp src/fs.cpp \
#       -lssl -lcrypto -lpthread
#
# Hint: if compilation fails, `docker build` will fail too — which
# is exactly what the autograder checks first.
RUN g++ -std=c++17 -O2 -o docuvault_server \
    src/server.cpp src/auth.cpp src/fs.cpp \
    -lssl -lcrypto -lpthread


# --- TODO 3: Create the data directory for block storage ---
# Your FileSystem class needs a directory to store block files and
# the index.  Create it here so it exists at container startup.
#
# The server's default data path is /data/store (see server.cpp main).
# Example:
#   RUN mkdir -p /data/store/blocks
RUN mkdir -p /data/store/blocks


# --- TODO 4: Expose the server port ---
# Tell Docker which port your server listens on.
#
# Example:
#   EXPOSE 8080
EXPOSE 8080


# --- Start the server (provided — do not change) ---
CMD ["./docuvault_server"]
