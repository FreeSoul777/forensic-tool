.PHONY: build run attach sync clean

IMAGE_NAME = forensic-tool
CONTAINER_NAME = forensic-dev
DOCKERFILE_PATH = docker/Dockerfile

# Цвета для вывода
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m

build:
	@echo "$(BLUE)🔨 Сборка Docker образа...$(NC)"
	@docker build -f $(DOCKERFILE_PATH) -t $(IMAGE_NAME) .
	@echo "$(GREEN)✅ Образ собран: $(IMAGE_NAME)$(NC)"

run:
	@echo "$(BLUE)🚀 Запуск контейнера...$(NC)"
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@docker run -it \
		--name $(CONTAINER_NAME) \
		--privileged \
		-v "$$(pwd):/app" \
		-v /var/log:/var/log:ro \
		-v /etc/passwd:/etc/passwd:ro \
		-v /etc/group:/etc/group:ro \
		-v forensic_data:/data \
		$(IMAGE_NAME)

attach:
	@echo "$(BLUE)🔌 Подключение к контейнеру...$(NC)"
	@docker exec -it $(CONTAINER_NAME) /bin/bash

sync:
	@echo "$(BLUE)🔄 Синхронизация кода...$(NC)"
	@docker cp . $(CONTAINER_NAME):/app/
	@echo "$(GREEN)✅ Код синхронизирован$(NC)"

clean:
	@echo "$(YELLOW)🧹 Очистка...$(NC)"
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@docker volume rm forensic_data 2>/dev/null || true
	@echo "$(GREEN)✅ Очистка завершена$(NC)"