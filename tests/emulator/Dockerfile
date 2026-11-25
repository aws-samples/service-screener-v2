# AWS Emulator image for local check tests.
# Build:  docker build --build-arg ARCH=$(uname -m | sed 's/arm64/aarch64/') -t aws-emulator tests/emulator
# Run (loopback only - never publish on all interfaces):
#   mkdir -p ~/.aws/emulator
#   docker run --rm --memory=2g -p 127.0.0.1:9297:9297 -e HOME="$HOME" \
#     -v "$HOME/.aws/emulator:$HOME/.aws/emulator" aws-emulator -p 9297 --idle-timeout 7200
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
ARG ARCH=x86_64
ADD https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest/aws-emulator-${ARCH}.rpm /tmp/aws-emulator.rpm
RUN rpm -i /tmp/aws-emulator.rpm && rm /tmp/aws-emulator.rpm \
 && mkdir -p /home/emulator && chown 1000 /home/emulator
USER 1000
ENV HOME=/home/emulator
ENV EMULATOR_TELEMETRY=off
EXPOSE 9297
ENTRYPOINT ["aws-emulator", "-b", "0.0.0.0"]
