FROM openjdk:17-jdk-alpine

WORKDIR /app

ARG APP_VERSION

ADD authorization-server-0.1.0-SNAPSHOT.jar App.jar

COPY target/ .

COPY target/mytest.jks src/main/resources/mytest.jks

#COPY themes/ src/main/resources/themes/

ENV JAVA_OPTS="-Dserver.forward-headers-strategy=native"

CMD ["java", "-jar", "App.jar"]