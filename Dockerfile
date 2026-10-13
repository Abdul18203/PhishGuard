FROM eclipse-temurin:25-jdk
WORKDIR /app
COPY mvnw pom.xml ./
COPY .mvn .mvn
COPY src src
RUN chmod +x mvnw && ./mvnw clean package -DskipTests
EXPOSE 8080
CMD ["sh", "-c", "java -jar target/*.jar"]