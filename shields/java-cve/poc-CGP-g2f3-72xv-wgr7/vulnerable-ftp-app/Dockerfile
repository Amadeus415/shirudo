FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app
COPY vulnerable-ftp-app/target/wgr7-vulnerable-ftp-app.jar /app/wgr7-vulnerable-ftp-app.jar
COPY commons-net-bytebuddy-guard/target/wgr7-epsv-guard.jar /app/wgr7-epsv-guard.jar

EXPOSE 8080
ENTRYPOINT ["java", "-XX:+StartAttachListener", "-jar", "/app/wgr7-vulnerable-ftp-app.jar"]
CMD ["serve", "8080"]
