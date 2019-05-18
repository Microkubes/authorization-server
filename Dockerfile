### Multi-stage build
FROM golang:1.10-alpine3.7 as build

RUN apk --no-cache add git curl openssh

RUN go get -u -v github.com/keitaroinc/goa/... && \
    go get -u -v github.com/asaskevich/govalidator && \
    go get -u -v github.com/keitaroinc/oauth2 && \
    go get -u -v github.com/gorilla/sessions && \
    go get -u -v github.com/gorilla/securecookie && \
    go get -u -v github.com/Microkubes/microservice-security/... && \
    go get -u -v github.com/Microkubes/microservice-tools/...

COPY . /go/src/github.com/Microkubes/authorization-server

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install github.com/Microkubes/authorization-server

### Main
FROM scratch

ENV API_GATEWAY_URL="http://localhost:8001"

COPY --from=build /go/src/github.com/Microkubes/authorization-server/config.json /config.json
COPY --from=build /go/bin/authorization-server /authorization-server
COPY public /public

EXPOSE 8080

CMD ["/authorization-server"]
