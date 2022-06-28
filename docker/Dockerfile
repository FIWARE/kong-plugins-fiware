FROM kong/go-plugin-tool:2.0.4-alpine-latest AS build-pep-plugin

COPY ./kong-pep-plugin /temp/pep-plugin

WORKDIR /temp/pep-plugin

RUN go build -o pep-plugin .

## build the lua version first
FROM kong-lua

USER root
COPY --from=build-pep-plugin /temp/pep-plugin /kong/go-plugins/
RUN chmod -R 777 /kong/go-plugins/
USER kong