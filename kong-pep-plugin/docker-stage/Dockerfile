FROM kong/go-plugin-tool:2.0.4-alpine-latest AS build-pep-plugin
COPY ./kong-pep-plugin /temp/pep-plugin
WORKDIR /temp/pep-plugin
RUN go build -o pep-plugin .
