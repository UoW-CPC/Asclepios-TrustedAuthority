# Build and run like this (with this Dockerfile in the current dir)
#
#     docker build -t myteep:v1 .
#     docker run  --device /dev/sgx -ti --name myteep myteep:v1
#


FROM ubuntu:18.04
#FROM python:3.7.5-slim

RUN apt update && apt upgrade -y && apt install -y build-essential git sudo wget

#
# Create a user account 'teep' that can sudo, and run from that account
#

ENV USER teep

RUN useradd -m -G sudo $USER; \
   sed -ie 's@%sudo.ALL=(ALL:ALL) ALL@%sudo   ALL=(ALL:ALL) NOPASSWD:ALL@' /etc/sudoers

WORKDIR /home/$USER
RUN mkdir teep-deployer
COPY entrypoint.sh teep-deployer/entrypoint.sh
#USER $USER
#WORKDIR /home/$USER
#ADD . $CONTAINER_HOME/teepdeployer

#
# Install OpenEnclave
#     see https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md
#

RUN \
     echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list; \
     wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add - ; \
     \
     echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list; \
     wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -; \
     \
     echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list; \
     wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -; \
     \
     sudo apt update; \
     sudo apt install -y clang-7 libssl-dev gdb libsgx-enclave-common libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave; \
     \
     echo ". /opt/openenclave/share/openenclave/openenclaverc" >> ~/.bashrc

#
#  Install python Conda-distribution
#

#RUN \
#    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh; \
#    chmod a+x  Miniconda3-latest-Linux-x86_64.sh; \
#    ./Miniconda3-latest-Linux-x86_64.sh -b; \
#    \
#    . ~/miniconda3/bin/activate; \
#    conda init bash; \
#    conda update -y conda
    
#
#  Install asclepios-teep dependencies
#

#RUN \
#    . ~/miniconda3/bin/activate; \
#    conda install -y pip ipython pycryptodome; \
#    pip install cbor aiocoap
    #python3 -m pip install cbor aiocoap
RUN apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt install python3.7 -y

# Make python 3.7 the default
RUN echo "alias python=python3.7" >> ~/.bashrc
RUN export PATH=${PATH}:/usr/bin/python3.7
RUN /bin/bash -c "source ~/.bashrc"

# Install pip
RUN apt install python3-pip -y
RUN python3.7 -m pip install --upgrade pip
RUN python3.7 -m pip install cbor aiocoap pycryptodome

WORKDIR /home/$USER/teep-deployer
#CMD ["./entrypoint.sh"]
