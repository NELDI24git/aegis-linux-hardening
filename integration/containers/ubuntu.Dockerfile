FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip openssh-server iproute2 nftables findutils && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
RUN python3 -m pip install --break-system-packages -e . pytest
CMD ["python3", "-m", "pytest", "-q"]
