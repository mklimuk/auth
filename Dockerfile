FROM alpine:3.3

ARG HUSAR_VERSION

# set the Warsaw timezone
RUN apk add --update tzdata && \
    cp /usr/share/zoneinfo/Europe/Warsaw /etc/localtime && \
    echo "Europe/Warsaw" >  /etc/timezone && \
    apk del tzdata

EXPOSE 8080

VOLUME /etc/husar

COPY assets/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
COPY dist/auth /usr/local/bin/auth
RUN mkdir -p /var/husar && echo "version: $HUSAR_VERSION" > /var/husar/version.yml

CMD /usr/local/bin/auth
