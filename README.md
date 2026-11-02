# Паттерн «Защищённый административный шлюз» (Secure Admin Gateway)

[![ci](https://github.com/Slava527/secure-admin-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Slava527/secure-admin-gateway/actions/workflows/ci.yml)

Прототип к курсовой работе: пять микросервисов, защищающих административный API
приложения в Yandex Cloud от неправомерного использования интерфейса (УБИ.068)
и перехвата/подмены административного трафика (УБИ.116).

| Сервис | Назначение |
|---|---|
| `sag-gateway` (+ `nginx`) | единая точка входа: TLS 1.3, mTLS, ограничение частоты, оркестрация проверок |
| `sag-request-verifier` | подпись запроса, метка времени, однократность nonce (`Redis`) |
| `sag-auth` | проверка JWT, признак 2FA, связь токена с сертификатом |
| `sag-authz` | роли, операция, сеть источника (`policy.yaml`) |
| `sag-audit` | журнал событий в JSON, метрики Prometheus `/metrics` |
| `admin-api` | защищаемый внутренний сервис (учебный административный API) |

## Структура репозитория

```
.github/workflows/ci.yml   конвейер CI: тесты, проверка манифестов, сквозные сценарии
services/<сервис>/         код, Dockerfile, requirements.txt каждого микросервиса
k8s/                       манифесты Kubernetes (namespace, Deployment, Service, NetworkPolicy)
kustomization.yaml         сборка манифестов и ConfigMap (Kustomize)
compose.yaml               запуск для отладки (Docker Compose)
deploy-minikube.sh         развёртывание в локальном кластере (minikube + Calico)
pki/gen-certs.sh           выпуск учебной PKI (ключи в репозиторий не попадают)
tools/                     клиент администратора, учебный IdP, демонстрация
tests/                     проверка логики безопасности сервисов
```

## Что нужно установить

* Docker (Docker Desktop в Windows/macOS) и Docker Compose v2;
* Python 3.10+ для клиента сценариев: `pip install -r tools/requirements.txt`;
* `openssl` (в Windows есть в Git Bash);
* для Kubernetes: `kubectl` и `minikube` **или** доступ к кластеру Yandex Managed Service for Kubernetes;
* для Yandex Cloud дополнительно: аккаунт с платёжным аккаунтом, `yc` CLI.

## 1. Выпуск сертификатов и ключей

```bash
bash pki/gen-certs.sh          # создаёт pki/out/*: УЦ, сертификат шлюза, admin, auditor, intruder, ключи JWT
```

## 2. Локальный запуск (Docker Compose)

```bash
docker compose up --build -d
docker compose ps
python tools/admin_client.py all        # все сценарии
docker compose logs audit               # журнал решений шлюза (JSON)
curl http://127.0.0.1:9100/metrics      # метрики
```

Ожидаемые результаты:

| Сценарий | Ожидание |
|---|---|
| `legit` | HTTP 200, список пользователей |
| `no-cert` (похищен только токен) | соединение разорвано на TLS |
| `intruder` (чужой самоподписанный сертификат) | соединение разорвано на TLS |
| `replay` (повтор перехваченного запроса) | первый 201, повтор 401 `replay detected` |
| `tamper` (подмена тела) | 401 `invalid request signature` |
| `stolen` (токен admin + сертификат auditor) | 401 `token does not belong to certificate owner` |
| `forbidden` (auditor пытается изменить данные) | 403 `operation not permitted for roles` |

## Демонстрация преподавателю

```bash
python tools/demo.py                 # пошагово: легитимные пользователи, затем нарушитель
```
Во втором окне терминала держите открытым журнал решений шлюза:
`kubectl -n sag logs -f -l app=sag-audit --prefix` (или `docker compose logs -f audit`).

## 3. Kubernetes локально (minikube) – имитация Yandex Managed Service for Kubernetes

```bash
docker compose down                   # освободить порт 8443
bash deploy-minikube.sh               # кластер с Calico, сборка образов, секреты, манифесты
kubectl -n sag get pods -o wide       # скриншот для курсовой
kubectl -n sag port-forward svc/sag-gateway 8443:443   # во втором окне, держать открытым
py tools/admin_client.py all
py tools/demo.py
kubectl -n sag logs -l app=sag-audit --tail=20
```

Ресурсы кластера можно изменить: `CPUS=4 MEMORY=6144 bash deploy-minikube.sh`.
Остановить кластер: `minikube stop`, удалить: `minikube delete`.

В Yandex Cloud секреты вместо `kubectl create secret` можно хранить в Yandex Lockbox
и передавать в кластер через External Secrets Operator.

## 4. Yandex Cloud

1. `yc init`; в консоли создать Docker-реестр в **Cloud Registry** и выполнить вход по инструкции сервиса.
2. Создать кластер **Managed Service for Kubernetes** с контроллером сетевых политик **Calico**
   и группу узлов (для демонстрации достаточно одного узла).
3. `yc managed-kubernetes cluster get-credentials <имя-кластера> --external`
4. Собрать и отправить образы:
   `docker build -t registry.yandexcloud.net/<REGISTRY_ID>/sag-<сервис>:1.0 services/<сервис>` и `docker push ...`
5. В `kustomization.yaml` раскомментировать блок `images` и указать `<REGISTRY_ID>`.
6. Выполнить шаги раздела 3, начиная с `kubectl apply -f k8s/00-namespace.yaml`.
7. `kubectl -n sag get svc sag-gateway` — внешний адрес балансировщика. Перевыпустить сертификат шлюза
   с этим адресом: `EXTRA_SAN=IP:<адрес> bash pki/gen-certs.sh`, обновить секрет, перезапустить шлюз
   (`kubectl -n sag rollout restart deploy/sag-gateway`), затем `SAG_URL=https://<адрес> python tools/admin_client.py all`.

Кластер и группа узлов тарифицируются почасово: после показа остановите или удалите их.
