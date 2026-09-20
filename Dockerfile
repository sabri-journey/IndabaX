FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY config ./config

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin defender
USER 10001:10001

ENV PYTHONPATH=/srv/src
EXPOSE 8080
CMD ["uvicorn", "defense.adapter:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
