FROM maven:3.9-eclipse-temurin-21

WORKDIR /workspace

COPY . .

RUN mvn -B package -DskipTests

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/workspace/target/app.jar"]
