FROM malware-analysis-lab-tools-base
WORKDIR /app
RUN groupadd -g 1000 lab && useradd -u 1000 -g 1000 -M -d /tmp/lab-home -s /usr/sbin/nologin lab
COPY run.py analyze.py triage.py dashboard.py gui_capture.py rules.yar ./
CMD ["sleep", "infinity"]
