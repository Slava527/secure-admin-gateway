# Многоэтапная сборка: зависимости ставятся на промежуточном этапе,
# в итоговый образ попадают только интерпретатор, библиотеки и код сервиса.
# В эксплуатации базовый образ закрепляется по дайджесту: python:3.12-slim@sha256:...
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /install /usr/local
WORKDIR /app
COPY . .
# запуск от непривилегированного пользователя
USER 10001
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
