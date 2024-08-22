# Use a Screener base image
FROM yingtingaws/screener-scheduler-base:latest 

RUN cd service-screener-v2

# TESTING
ENV AWS_ACCESS_KEY_ID="ASIAQ3EGRJVGWEK4QYPP"
ENV AWS_SECRET_ACCESS_KEY="jm7Ym+fSbYzq3e6Q+T8Q7TPVkoKIRN3Swk9FtW89"
ENV AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEIL//////////wEaCXVzLWVhc3QtMSJHMEUCIBrkVqFsrDqGMIkNVmWV+QkBUP2LyNwukgnjwWE4YpKBAiEA3CGxM15mBpDG6lzkxvh59RSg17omMIFN8BNtGPRtmXkq8AIIiv//////////ARAAGgwwNTgyNjQyMTA3NjUiDDA55xSVdLMaFNlKQSrEAgGwaB9elfEgLDNJrUMExRd2Jijki+JXK2YWxujOx4NIHhI/adD7Yt6kbRd/g5R35U+EiwCUllUwqtwaBiUaaw6A8brOzF9XldAFX/IoZCH7gmWb+qY8tGJpDPrdEkwusVmlXm0oog3S+eEpnUy0v5SUdvlGNkC3QMgLm+VKwrYsS3YZiveoIyTrXgX4mqlNm/r6PBpdWkykhA8QlqE0SKb3PpyxnISLONbRJCMCGBhRzyP3lX7wgxuKXLc4q2guEgy0jWA+KumIZyZYOpYsXkB+XVvsnQJEb/huljB91vPLPgVBYMYI8kBuw+ruQWk/P4afvCJzZRIPG8/6SBCENOTH0NYSsyXsDnzWDPaU7GN/pp5/8BQ/WnTo2FRf5UUHm208YAYW65GRWCLCFo5MiT0HJfhXtS7n8qYa+dljFRiWfIi1RDCngJy2BjqnAb7UX1NygEfZrJpzNZOo2FQlob5dBXlLKplG5IcVxMYQL70SD4kGyhT+6woQAWUEaMIGecOiTNYDDnpu4DPqkdvUoOuVwPlQzvDoPLGX4Addxeur9vOXKSUEu+eSbE2fj873aL/MqW4i6W319fHvRw6PeTk8BSamRdzFAcx1tRHKzhC2XowfLRqAK2QQ6ngUfRF6prJcDSlQgtP85FA2LujzYjUIz4xq"

# Copy the script
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh

# Make the script executable
RUN chmod +x /tmp/docker-entrypoint.sh

# Set the CMD to run the script
RUN cat /tmp/docker-entrypoint.sh
ENTRYPOINT ["/tmp/docker-entrypoint.sh"]