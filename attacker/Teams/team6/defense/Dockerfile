# Use the official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container to /app
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app/

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Define environment variable for the model path
ENV MODEL_PATH=/app/model/malware_detection_model.joblib

# Run app.py when the container launches
CMD ["python", "apps.py"]

# TO BUILD IMAGE:
# docker build -t defender .

# TO RUN IMAGE:
# docker run -itp 8080:8080 defender