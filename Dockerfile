# The first instruction is what image we want to base our container on
# We Use an official Python runtime as a parent image
FROM python:3.7-slim

# The enviroment variable ensures that the python output is set straight
# to the terminal with out buffering it first
#ENV PYTHONUNBUFFERED 1

# create root directory for our project in the container
RUN mkdir /TA

# Set variables for project name, and where to place files in container.
#ENV PROJECT=SSEServer
ENV CONTAINER_HOME=/TA
#ENV CONTAINER_PROJECT=$CONTAINER_HOME/$PROJECT

# Set the working directory to /sse_server
WORKDIR $CONTAINER_HOME
#RUN mkdir lodgs

# Copy the current directory contents into the container at /music_service
ADD . $CONTAINER_HOME

COPY entrypoint.sh /entrypoint.sh

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

#ENTRYPOINT ["./entrypoint.sh"]
#ENTRYPOINT [ "python3" ]
CMD ["./entrypoint.sh"]