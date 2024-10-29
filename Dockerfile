# Use an official Python runtime as the base image
FROM ghcr.io/liatrio/python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file to the working directory
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the working directory
COPY . .

# Set the command to run the application
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]