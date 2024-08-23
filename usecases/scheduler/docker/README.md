This Docker image is currently hosted on yingtingaws/screener-scheduler repository. If you would like to update/ modify it, you can deploy it locally.

## Pre-requisites
Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) to set up Docker in your environment.

## Deployment Guide 
1. Fork this repository or download the Dockerfiles (base image is in ./docker-base-image folder)
2. After making changes to the Dockerfile, run the following commands
```
## Build Docker image
docker build -t <docker username>/<repository>
## Run Docker 
docker run <docker username>/<repository>
## Tag Docker image
docker tag <docker username>/<repository> <docker username>/<repository>:<tag name>
## Push to Dockerhub
docker push <docker username>/<repository>:latest  
```

If you would like to use your own Docker image, go to ../src/infra/service_screener_automation/service_screener_automation_stack.py and change repository image source in:
```
image=ecs.ContainerImage.from_registry("yingtingaws/screener-scheduler:latest")
```

