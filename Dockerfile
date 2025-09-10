FROM python:3.12-slim

# Node для сборки фронта
RUN apt-get update && apt-get install -y nodejs npm git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Сборка фронта
RUN npm install
RUN npm run build

# Установка зависимостей Python
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "email_checker_server.py"]
