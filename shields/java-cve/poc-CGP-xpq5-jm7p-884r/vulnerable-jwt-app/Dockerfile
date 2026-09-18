FROM maven:3.9.11-eclipse-temurin-8 AS build

WORKDIR /build

COPY vulnerable-jwt-app/pom.xml ./vulnerable-jwt-app/pom.xml
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -f vulnerable-jwt-app/pom.xml dependency:go-offline

COPY vulnerable-jwt-app/src/ ./vulnerable-jwt-app/src/
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -f vulnerable-jwt-app/pom.xml package

# The supplied guard is compiled for Java 21 (class-file version 65). Use the
# JDK image because its Attach API is needed to load the agent at runtime.
FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app
COPY --from=build /build/vulnerable-jwt-app/target/vulnerable-jwt-app.jar ./vulnerable-jwt-app.jar
COPY jjwt-bytebuddy-guard/jjwt-bytebuddy-guard.jar ./jjwt-bytebuddy-guard.jar

EXPOSE 8080
ENTRYPOINT ["java", "-XX:+StartAttachListener", "-jar", "/app/vulnerable-jwt-app.jar"]
CMD ["serve"]
