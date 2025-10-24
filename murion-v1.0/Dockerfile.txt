# Stage 1: Build stage
FROM eclipse-temurin:24-jdk AS builder

WORKDIR /app

# Install Maven
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pom.xml .
COPY src src

# Build the application
RUN mvn dependency:go-offline -B
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:24-jdk

WORKDIR /app

COPY --from=builder /app/target/*.jar /app/app.jar

EXPOSE 9090

ENTRYPOINT ["java", "-jar", "app.jar"]
