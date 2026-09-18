FROM maven:3.9.11-eclipse-temurin-8 AS build

WORKDIR /build

COPY vulnerable-jwt-app/pom.xml ./vulnerable-jwt-app/pom.xml
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -f vulnerable-jwt-app/pom.xml dependency:go-offline

COPY vulnerable-jwt-app/src/ ./vulnerable-jwt-app/src/
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -f vulnerable-jwt-app/pom.xml package

FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app
COPY --from=build /build/vulnerable-jwt-app/target/cgp-753c-vulnerable-jwt-app.jar ./cgp-753c-vulnerable-jwt-app.jar
COPY jjwt-bytebuddy-guard/target/cgp-753c-jjwt-zip-guard.jar ./cgp-753c-jjwt-zip-guard.jar

EXPOSE 8080
ENTRYPOINT ["java", "-XX:+StartAttachListener", "-jar", "/app/cgp-753c-vulnerable-jwt-app.jar"]
CMD ["8080"]
