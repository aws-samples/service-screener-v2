# Use a Screener base image
FROM yingtingaws/screener-scheduler-base:latest 

RUN cd service-screener-v2

# Copy the script
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh

# Make the script executable
RUN chmod +x /tmp/docker-entrypoint.sh

# Set the CMD to run the script
RUN cat /tmp/docker-entrypoint.sh
ENTRYPOINT ["/tmp/docker-entrypoint.sh"]