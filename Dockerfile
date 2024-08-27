FROM amazoncorretto:17.0.11-alpine3.18

LABEL maintener="darcos@banred.fin.ec"
LABEL Description="JWE BR"

RUN apk update && apk upgrade

RUN apk add tzdata && apk add shadow

RUN apk cache clean && rm -rf /var/cache/apk/*

ENV TZ=America/Guayaquil

ARG SERVER_PORT=8443
ARG user=devopsa
ARG group=devopsa
ARG home=/home/$user
ARG keyalias=ws-security-spring-boot
ARG domain=banred.fin.ec
ARG organization=BANRED
ARG city=Guayaquil
ARG KEYSTORE=certs/keystore/*.jks
ARG TRUSTSTORE=certs/truststore/*.jks
ARG JAR_FILE=target/*.jar

RUN groupadd -g 1337 $user && useradd -d $home -u 1337 -s /bin/bash -g $group $user

RUN mkdir -p $home/app/logs/  && mkdir -p $home/app/certs/ && chown -R $user:$group $home/app/

RUN mkdir -p /etc/ssl/certs/

RUN keytool -genkey -alias $keyalias -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -storetype PKCS12 -keystore /etc/ssl/certs/localhost.p12 -dname CN=$domain,OU=$organization,O=$organization,L=$city,C=CN -validity 3650 -storepass $SSL_TRUSTSTORE_PASSWORD -keypass $SSL_KEYSTORE_PASSWORD -ext san=dns:$domain
#TODO: UNCOMMENT CERTS FOR MTLS
# COPY ${KEYSTORE} $home/app/certs/keystore.jks
# COPY ${TRUSTSTORE} $home/app/certs/truststore.jks
#RUN chown -R $user:$group $home/app/ && $user:$group /etc/ssl/certs/ && chmod -R 700 /etc/ssl/certs/
#TODO: DELETE BELOW FOR MTLS
RUN chown -R $user:$group /etc/ssl/certs/ && chmod -R 700 /etc/ssl/certs/


USER $user

WORKDIR $home/app/

COPY ${JAR_FILE} app.jar

EXPOSE $SERVER_PORT

ENTRYPOINT ["java","-jar","app.jar"]