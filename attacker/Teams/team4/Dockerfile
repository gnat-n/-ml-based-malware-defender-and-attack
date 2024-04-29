
# Use the official Python image as base
FROM python:3.12.2-slim

# Set environment variables
ENV PORT=8080

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev

# RUN pip3 install envparse flask gevent yara-python
# Set the working directory in the container
#COPY requirements.txt /app
WORKDIR /app
COPY requirements.docker.txt .
RUN pip3 install -r requirements.docker.txt

# Copy the current directory contents into the container at /app
COPY . /app


# Expose the port the app runs on
EXPOSE $PORT

# Run the application
CMD ["python", "app.py", "$PORT"]
