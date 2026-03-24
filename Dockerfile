FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY custom_components /app/custom_components
COPY jablotron_re_tools.py /app/
COPY jablotron_usb_debug.py /app/
COPY jablotron_user_tool.py /app/
COPY jablotron_event_tool.py /app/
COPY export_cfg_tool.py /app/
COPY import_cfg_tool.py /app/
COPY flexi_pcap_tool.py /app/

RUN pip install --no-cache-dir .

VOLUME ["/data"]

EXPOSE 8443

CMD ["jablotron-api-server", "server"]
