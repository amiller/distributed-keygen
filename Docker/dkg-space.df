
# Base image for creating DKG-Distributed Key Generation
#  select which ubuntu release you want and comment out the other
#
FROM ubuntu:trusty
#
# FROM ubuntu:xenial

RUN apt-get update && \
  apt-get install -y git apt-utils curl tree wget flex bison nano

# Lots of stuff to install just for the general environment
#  C/C++ dev inplace for 4.8 to 6.X, default alternative set to gcc/g++ 6.X
RUN apt-get install build-essential software-properties-common -y && \
  add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
  apt-get update && \
  apt-get install gcc-snapshot -y && \
  apt-get update && \
  apt-get install gcc-6 g++-6 -y && \
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-6 60 --slave /usr/bin/g++ g++ /usr/bin/g++-6 && \
  apt-get install gcc-4.8 g++-4.8 -y && \
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 60 --slave /usr/bin/g++ g++ /usr/bin/g++-4.8;

RUN apt-get install -y libtool autotools-dev automake pkg-config cmake

RUN apt-get install -y gcc-multilib  g++-multilib  libgnutls28-dev  libgcrypt11-dev
 
# Placing in root directory, can be removed later
RUN mkdir GMP && wget -P /tmp  https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2 && \
  tar -xvf  ./tmp/gmp-6.1.2.tar.bz2 -C /GMP --strip-components=1 && \
  cd /GMP && \
  ./configure && \
  make && \
##  make check
  make install 

# Placing in root directory, can be removed later
RUN mkdir PBC && wget -P /tmp https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
  tar -xvf  ./tmp/pbc-0.5.14.tar.gz -C /PBC --strip-components=1 && \
  cd /PBC && \
  ./configure && \
  make && \
  make install

# The user is root, but put not putting in the root directory
RUN cd ~ && git clone https://github.com/amiller/distributed-keygen.git   && \
  cd ~/distributed-keygen/PBC && \
  make clean && \
  make && \
  cd ~/distributed-keygen/src && \
  make clean && \
  make

WORKDIR /root/distributed-keygen

RUN echo "Base DKG image complete"

