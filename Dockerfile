# PcapXray — https://github.com/srixivas/PcapXray
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz \
    python3-tk \
    python3-pip \
    python3-pil \
    python3-pil.imagetk \
    git \
    libx11-dev \
    libnss3 \
    libx11-xcb1 \
    libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/srixivas/PcapXray

RUN pip3 install --upgrade -r PcapXray/requirements.txt

WORKDIR PcapXray/Source
CMD ["python3", "main.py"]
