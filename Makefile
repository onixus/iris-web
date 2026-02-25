.PHONY: help build up down restart logs pull deploy

COMPOSE = docker compose

help: ## Показать справку
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Пересобрать образ app без кэша
	$(COMPOSE) build --no-cache app

up: ## Запустить все сервисы
	$(COMPOSE) up -d

down: ## Остановить все сервисы
	$(COMPOSE) down

restart: ## Перезапустить app и worker (без пересборки)
	$(COMPOSE) restart app worker

logs: ## Показать логи app
	$(COMPOSE) logs -f app

pull: ## git pull + перезапустить app/worker
	git pull
	$(COMPOSE) restart app worker

deploy: ## Полный редеплой: pull + build + restart
	git pull
	$(COMPOSE) build --no-cache app
	$(COMPOSE) up -d
