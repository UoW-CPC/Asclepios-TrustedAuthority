## Running the demo in a single docker container

1. Build the docker image

       docker build -t myteep:v1 .

2. To use SGX inside the container you must give the container access
   to /dev/sgx with `--device /dev/sgx`.

   If you don't want to `git clone` this remote repository inside the
   instance, simply run the instance with this local repo mounted as
   `teep.git` inside.

   I usually also add `--rm` to delete the instance when it quits to
   prevent the accumulation of a lot of garbage instances.

       docker run  --device /dev/sgx -v $(pwd):/home/teep/teep.git \
         --rm -ti myteep:v1

3. Inside the container, you can get a squeaky clean version of the
   repository by cloning it.  Step into the cloned repo and build.

       git clone teep.git
       cd teep
       make
      
      
4. Run the demo by first starting the server, and then starting the
   client.

       export AZDCAP_DEBUG_LOG_LEVEL=0
       python -c 'import simple; simple.start_server(port=7777)' &
      
       sleep 1
       python -c 'import simple; simple.sealingtest("coap://127.0.0.1:7777/teep")'
      
      
   This should print out

       Ok, Created file /tmp/myTmpFile-07qtYE.
       Host: Enclave library /tmp/myTmpFile-07qtYE
       Host: Enclave successfully created.
       Ok, Created file /tmp/myTmpFile-zimQBn.
       Host: Enclave library /tmp/myTmpFile-zimQBn
       Host: Enclave successfully created.
       b'These data are my secrets encrypted to to instance 0'
       b'These data are my secrets encrypted to to instance 0'
      

   The last two lines are the interesting ones.  Since they are in
   plain text, they show that the server was able to seal the data to
   the platform and later decrypt it and return it to the client over
   an encrypted channel.




## Running the server in one docker instance and the client in another

Get the host's public ip:

    # sudo apt install -y iproute2
    hostip=$(ip route get 1.1.1.1 | cut -d\  -f7)
    echo hostip=$hostip

Start the server, and publish the intance's port on some host port:

    docker run  --device /dev/sgx -v $(pwd):/home/teep/teep.git \
        --publish $hostip:7766:7777/udp --rm -ti myteep:v1
    git clone teep.git; cd teep; make; export AZDCAP_DEBUG_LOG_LEVEL=0
    python -c 'import simple; simple.start_server(port=7777)'

and start the client:

    docker run  --device /dev/sgx -v $(pwd):/home/teep/teep.git --rm -ti myteep:v1
    git clone teep.git; cd teep; make; export AZDCAP_DEBUG_LOG_LEVEL=0
    python -c 'import simple; simple.sealingtest("coap://'${hostip:?}':7766/teep")'
