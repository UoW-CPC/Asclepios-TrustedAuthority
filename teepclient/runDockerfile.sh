docker rmi -f teep:v1
docker build -t teep:v1 .
docker run -v $(pwd):/home/teep/teep-deployer --network="host" --rm -ti teep:v1
