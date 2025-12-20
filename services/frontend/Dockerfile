FROM nginx:alpine

# Копируем конфигурацию Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Копируем статические файлы и шаблоны
COPY templates/ /usr/share/nginx/html/templates/
COPY static/ /usr/share/nginx/html/static/

# Создаем index.html для редиректа
RUN echo '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=/templates/dashboard.html"></head></html>' > /usr/share/nginx/html/index.html

# Открываем порт
EXPOSE 80

# Запуск Nginx
CMD ["nginx", "-g", "daemon off;"]

