# FIWARE Kong Plugins

[![](https://nexus.lab.fiware.org/repository/raw/public/badges/chapters/api-management.svg)](https://www.fiware.org/developers/catalogue/)
[![License badge](https://img.shields.io/github/license/FIWARE/kong-plugins-fiware.svg)](https://opensource.org/licenses/MIT)
<br>
![Status](https://nexus.lab.fiware.org/static/badges/statuses/incubating.svg)

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

## Integration tests

Some plugins connect kong to external components. In order to assure them working in real environments, an integration-test framework based on [k3s](https://k3s.io/) is provided. The tests are executed using the [k3s-maven-plugin](https://github.com/kokuwaio/k3s-maven-plugin). 
The tests itself are written using [Junit5](https://junit.org/junit5/docs/current/user-guide/). 

### Usage

The tests use the local docker-image "fiware/kong:0.0.1". If a different one should be used, either provide it with that tag or change it inside the [kong.yaml](./it/src/test/k3s/kong.yaml). The tests can be executed via ```mvn integration-test```. For local development, a k3s-setup can be started with ```mvn k3s:create k3s:start k3s:image k3s:kubectl```. Tear down afterwards is executed via ```mvn k3s:rm```.
