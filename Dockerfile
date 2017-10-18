### Multi-stage build
FROM golang:1.8.3-alpine3.6 as build

RUN apk --no-cache add git curl openssh

COPY keys/id_rsa /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh/id_rsa && \
    echo -e "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config && \
    git config --global url."ssh://git@github.com:".insteadOf "https://github.com"

RUN go get -u github.com/axw/gocov/gocov && \
    go get -u github.com/AlekSi/gocov-xml && \
    go get -u gopkg.in/h2non/gock.v1 && \
    go get -u github.com/goadesign/goa/... && \
    go get -u github.com/goadesign/oauth2 && \
    go get -u gopkg.in/mgo.v2 && \
    go get -u github.com/afex/hystrix-go/hystrix && \
    go get -u github.com/satori/go.uuid && \
    go get -u github.com/dgrijalva/jwt-go && \
    go get -u github.com/gorilla/sessions && \
    go get -u github.com/gorilla/securecookie

RUN go get -u github.com/JormungandrK/microservice-tools && \
    go get -u github.com/JormungandrK/microservice-security/...

COPY . /go/src/github.com/JormungandrK/authorization-server
RUN go install github.com/JormungandrK/authorization-server

### Main
FROM alpine:3.6

COPY --from=build /go/bin/authorization-server /usr/local/bin/authorization-server
COPY config.json /config.json
COPY public /public
EXPOSE 8080

ENV SERVICE_CONFIG_FILE="config.json"
ENV API_GATEWAY_URL="http://localhost:8001"

CMD ["/usr/local/bin/authorization-server"]
