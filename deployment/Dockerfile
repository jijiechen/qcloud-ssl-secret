FROM golang:1.15 as builder

COPY . /go/src/qcloud-ssl-secret
RUN go mod tidy
RUN go build . -o /go/bin/qcloud-ssl-secret



FROM alpine:3.13.5
VOLUME /etc/qcloud-ssl-secret/
ENV SECRET_ID ""
ENV SECRET_KEY ""

COPY --from=builder /go/bin/qcloud-ssl-secret /usr/local/bin/qcloud-ssl-secret
COPY --from=builder /go/src/qcloud-ssl-secret/deployment/tls.crt /etc/qcloud-ssl-secret/
COPY --from=builder /go/src/qcloud-ssl-secret/deployment/tls.key /etc/qcloud-ssl-secret/

EXPOSE 8080/tcp
ENTRYPOINT [ "/usr/local/bin/qcloud-ssl-secret" ]



