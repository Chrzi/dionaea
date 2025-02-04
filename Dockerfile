FROM ubuntu:18.04
ENV DEBIAN_FRONTEND noninteractive
#
# Include dist
ADD dist/ /root/dist/
#
# Install dependencies and packages
RUN apt-get update && \
    apt-get update -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	check \
	cmake \
	cython3 \
	git \
    libcap2-bin \
	libcurl4-openssl-dev \
	libemu-dev \
	libev-dev \
	libglib2.0-dev \
	libloudmouth1-dev \
	libnetfilter-queue-dev \
	libnl-3-dev \
	libpcap-dev \
	libssl-dev \
	libtool \
	libudns-dev \
	procps \
	gcc \
	python3 \
	python3-dev \
	python3-wheel \
	python3-setuptools \
	python3-boto3 \
	python3-bson \
	python3-yaml \
	python3-pip \
    libsnappy-dev \
	fonts-liberation && \

	pip3 install cffi && \
	pip3 install pynsq
	#pip3 install git+https://github.com/bgeisberger/gnsq.git

ADD . /root/dionaea
# Get and install dionaea
    # Latest master is unstable, SIP causes crashing
    #git clone --depth=1 https://github.com/Chrzi/dionaea.git /root/dionaea/ && \
RUN cd /root/dionaea && \
    #git checkout 1426750b9fd09c5bfeae74d506237333cd8505e2 && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea .. && \
    make && \
    make install && \
#
# Setup user and groups
    addgroup --gid 2000 dionaea && \
    adduser --system --no-create-home --shell /bin/bash --uid 2000 --disabled-password --disabled-login --gid 2000 dionaea && \
    setcap cap_net_bind_service=+ep /opt/dionaea/bin/dionaea && \
#
# Supply configs and set permissions
    chown -R dionaea:dionaea /opt/dionaea/var && \
    rm -rf /opt/dionaea/etc/dionaea/* && \
    mv /root/dist/etc/* /opt/dionaea/etc/dionaea/ && \
#
# Setup runtime and clean up
    apt-get purge -y \
      build-essential \
      ca-certificates \
      check \
      cmake \
      cython3 \
      git \
      libcurl4-openssl-dev \
      libemu-dev \
      libev-dev \
      libglib2.0-dev \
      libloudmouth1-dev \
      libnetfilter-queue-dev \
      libnl-3-dev \
      libpcap-dev \
      libssl-dev \
      libtool \
      libudns-dev \
      python3 \
      python3-dev \
      python3-boto3 \
      python3-bson \
      python3-yaml && \
#
    apt-get install -y \
      ca-certificates \
      python3 \
      python3-boto3 \
      python3-bson \
      python3-yaml \
      libcurl4 \
      libemu2 \
      libev4 \
      libglib2.0-0 \
      libnetfilter-queue1 \
      libnl-3-200 \
      libpcap0.8 \
      libpython3.6 \
      libudns0 && \
#
    apt-get autoremove --purge -y && \
    apt-get clean && \
    rm -rf /root/* /var/lib/apt/lists/* /tmp/* /var/tmp/*
#
# Start dionaea
USER dionaea:dionaea
CMD ["/opt/dionaea/bin/dionaea", "-u", "dionaea", "-g", "dionaea", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg", "-l", "all"]
