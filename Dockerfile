# wriote docker file for this fast api rest api
# Use the official image as a parent image
FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8

# Set the working directory
WORKDIR /app


# Copy the current directory contents into the container at /app
COPY /app /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


#define the environment variables
#ENV aws_access_key_id=
#ENV VARIABLE_NAME=app


# Make port 80 available to the world outside this container
EXPOSE 80
