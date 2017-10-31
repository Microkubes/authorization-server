### Multi-stage build
FROM golang:1.8.3-alpine3.6 as build

RUN apk --no-cache add git curl openssh

RUN go get -u -v github.com/axw/gocov/gocov && \
    go get -u -v github.com/AlekSi/gocov-xml && \
    go get -u -v gopkg.in/h2non/gock.v1 && \
    go get -u -v github.com/goadesign/goa/... && \
    go get -u -v github.com/goadesign/oauth2 && \
    go get -u -v gopkg.in/mgo.v2 && \
    go get -u -v github.com/afex/hystrix-go/hystrix && \
    go get -u -v github.com/satori/go.uuid && \
    go get -u -v github.com/dgrijalva/jwt-go && \
    go get -u -v github.com/gorilla/sessions && \
    go get -u -v github.com/gorilla/securecookie && \
    go get -u -v github.com/JormungandrK/microservice-tools && \
    go get -u -v github.com/JormungandrK/microservice-security/...

COPY . /go/src/github.com/JormungandrK/authorization-server
RUN go install github.com/JormungandrK/authorization-server

### Main
FROM alpine:3.6

COPY --from=build /go/bin/authorization-server /usr/local/bin/authorization-server
COPY public /public
EXPOSE 8080

ENV API_GATEWAY_URL="http://localhost:8001"

CMD ["/usr/local/bin/authorization-server"]
