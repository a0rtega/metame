FROM debian:stable

RUN apt update && apt install -y \
                build-essential \
		cmake \
		python-pip \
		git \
                time \
	&& git clone https://github.com/radare/radare2 \
        && cd radare2 \
        && sys/install.sh \
        && cd && git clone https://github.com/keystone-engine/keystone/ \
        && cd keystone \
        && mkdir build \
        && cd build/ \
        && ../make-share.sh \
        && make install \
        && ldconfig \ 
	&& pip install metame simplejson \
	&& rm -rf /var/lib/apt/lists/*

