# Use a Screener base image
FROM yingtingaws/screener-scheduler-base:latest 

RUN cd service-screener-v2

ENV AWS_ACCESS_KEY_ID="AKIAQ3EGRJVG3QBJQRNR"
ENV AWS_SECRET_ACCESS_KEY="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"
ENV AWS_DEFAULT_REGION="ap-southeast-1"

# Copy the script
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh

# Make the script executable
RUN chmod +x /tmp/docker-entrypoint.sh

# Set the CMD to run the script
RUN cat /tmp/docker-entrypoint.sh
ENTRYPOINT ["/tmp/docker-entrypoint.sh"]