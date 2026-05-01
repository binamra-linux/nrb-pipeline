# Simulated partially hardened Nepali fintech app
FROM python:3.9-slim

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Still has hardcoded secret - NRB violation
ENV SECRET_KEY=mysecretkey

USER appuser

EXPOSE 8000 80

CMD ["python3", "app.py"]
