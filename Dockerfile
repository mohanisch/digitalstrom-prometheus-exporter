FROM alpine:3.12

RUN apk add --no-cache python3 \
              python3-dev \
              py3-pip  \
    && pip install prometheus-client==0.11.0

COPY dss_exporter.py /dss_exporter.py
RUN chmod 755 /dss_exporter.py

EXPOSE 9184
ENTRYPOINT ["/dss_exporter.py"]
