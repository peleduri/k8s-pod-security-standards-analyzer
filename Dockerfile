FROM cgr.dev/chainguard/python:latest-dev as dev

WORKDIR /app

RUN python -m venv venv
ENV PATH="/app/venv/bin":$PATH
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

FROM cgr.dev/chainguard/python:latest-dev

WORKDIR /app

# Copy application code
COPY analyzer.py .
COPY --from=dev /app/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Stream the log file to stdout and run the main application
ENTRYPOINT ["/bin/bash", "-c", "python analyzer.py & while [ ! -f /var/log/security-analysis.log ]; do sleep 1; done; tail -f /var/log/security-analysis.log"]
