FROM fedora:latest
RUN dnf -y install python3 python3-pip openssh-server iproute findutils nftables && dnf clean all
WORKDIR /src
COPY . /src
RUN python3 -m pip install -e . pytest
CMD ["python3", "-m", "pytest", "-q"]
