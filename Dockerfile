### Multi-stage build
FROM jormungandrk/goa-build as build

COPY . /go/src/github.com/Microkubes/authorization-server
RUN go install github.com/Microkubes/authorization-server

### Main
FROM alpine:3.7

COPY --from=build /go/bin/authorization-server /usr/local/bin/authorization-server
COPY public /public
EXPOSE 8080

ENV API_GATEWAY_URL="http://localhost:8001"

CMD ["/usr/local/bin/authorization-server"]
