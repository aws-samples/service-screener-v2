# Use a Screener base image
FROM yingtingaws/screener-scheduler-base:latest 

RUN cd service-screener-v2

ENV AWS_ACCESS_KEY_ID="AKIAQ3EGRJVGVGTSQSEX"
ENV AWS_SECRET_ACCESS_KEY="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"
ENV AWS_DEFAULT_REGION="us-east-1"

# Copy the script
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh

# Make the script executable
RUN chmod +x /tmp/docker-entrypoint.sh

# Set the CMD to run the script
RUN cat /tmp/docker-entrypoint.sh
ENTRYPOINT ["/tmp/docker-entrypoint.sh"]