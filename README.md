# FIWARE Kong Plugins

This repository contains Kong plugins provided by FIWARE. These allow to extend 
the API Gateway Kong by further functionalities required for FIWARE-based 
environments.


## FIWARE Kong build

There is a specific Kong build, that incorporates all these plugins. When using this build, 
the plugins do not need to be installed separately. 
It can be found on [quay.io/fiware/kong](https://quay.io/repository/fiware/kong?tab=tags).

It is automatically build when there is a new release of the plugins. 



## Tests

The [pongo framework](https://github.com/Kong/kong-pongo) is used for testing Kong plugins. 
This framework runs the tests for the plugins and ensures that the system is configured for Kong, 
including fetching any dependencies. In addition, it sets up a test Kong environment so that one 
can run plugins in real time.

In order to run the tests for a plugin, firstly a Docker image of pongo has to be build. This can 
be done by using the provided [Dockerfile](./pongo/Dockerfile):
```shell
# Set pongo version
PONGO_VERSION=1.1.0

docker build --tag="pongo:$PONGO_VERSION" --build-arg PONGO_VERSION \
    -f "./pongo/Dockerfile" .
```

The pongo framework requires a valid rockspec, but this is only provided 
as [mustache](http://mustache.github.io/) template. 
To create the rockspec file, set the required variables and run mustache:
```shell
echo GITHUB_ORGANISATION: fiware >> values.yaml
echo GITHUB_REPO: kong-plugins-fiware >> values.yaml
# Version is required for a valid rockspec, but can be set to any value for the tests
echo VERSION: 1.0.0 >> values.yaml

# Run mustache for, e.g., the ngsi-ishare-policies plugin:
docker run -v `pwd`:/data --rm -it \
	coolersport/mustache values.yaml kong-plugin-ngsi-ishare-policies/rockspec.mustache \
	> kong-plugin-ngsi-ishare-policies/kong-plugin-ngsi-ishare-policies-1.0.0-1.rockspec
```

Finally, the tests for, e.g., the ngsi-ishare-policies plugin can be run with the following script:
```shell
# Should match the version of the built image
PONGO_VERSION=1.1.0

# Set the Kong version to be used, e.g., 2.8.1
KONG_VERSION=2.8.1

# Run pongo
PONGO_PLUGIN_SOURCE=./kong-plugin-ngsi-ishare-policies ./pongo/pongo-docker.sh run
```
