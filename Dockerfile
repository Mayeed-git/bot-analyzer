# Self-contained Dockerfile for Bot Detection Analyzer
FROM openjdk:11-jdk-slim

# Set working directory
WORKDIR /app

# Copy the Java source file
COPY src/BotDetectionAnalyzer.java .

# Copy the sample log file directly into the container
COPY sample-log.log .

# Compile the Java application
RUN javac BotDetectionAnalyzer.java

# Set the entry point to run with the embedded log file
ENTRYPOINT ["java", "BotDetectionAnalyzer", "sample-log.log"]

# Metadata
LABEL description="Self-contained Bot Detection Analyzer with embedded sample data"
LABEL version="1.0"
