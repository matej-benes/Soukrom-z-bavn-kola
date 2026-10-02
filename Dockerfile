FROM python:3.12-slim
WORKDIR /app
COPY app.py index.html school_data.json ./
ENV PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]
