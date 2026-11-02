#!/usr/bin/env bash
# Развёртывание паттерна в локальном кластере Kubernetes (minikube) – имитация
# Yandex Managed Service for Kubernetes на ноутбуке.
# Запуск из папки проекта:  bash deploy-minikube.sh
# Требуется: Docker Desktop (запущен), minikube, kubectl, выпущенные сертификаты (bash pki/gen-certs.sh).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"
CPUS="${CPUS:-2}"
MEMORY="${MEMORY:-4096}"

[ -f pki/out/server.crt ] || { echo "Сначала выпустите сертификаты: bash pki/gen-certs.sh"; exit 1; }

echo "== 1. Кластер (аналог Managed Service for Kubernetes с контроллером сетевых политик Calico)"
if ! minikube status >/dev/null 2>&1; then
  minikube start --driver=docker --cni=calico --cpus="$CPUS" --memory="$MEMORY"
fi
minikube addons enable metrics-server >/dev/null || true   # нужен для HorizontalPodAutoscaler

echo "== 2. Сборка образов и загрузка в кластер (аналог публикации в Cloud Registry)"
for s in gateway request-verifier auth authz audit admin-api; do
  echo "   sag/$s:1.0"
  docker build -q -t "sag/$s:1.0" "services/$s" >/dev/null
  minikube image load --overwrite=true "sag/$s:1.0"
done

echo "== 3. Пространство имён и секреты (аналог Lockbox и Certificate Manager)"
kubectl apply -f k8s/00-namespace.yaml
kubectl -n sag create secret generic sag-gateway-tls \
  --from-file=server.crt=pki/out/server.crt \
  --from-file=server.key=pki/out/server.key \
  --from-file=ca.crt=pki/out/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n sag create secret generic sag-jwt \
  --from-file=jwt-public.pem=pki/out/jwt-public.pem \
  --dry-run=client -o yaml | kubectl apply -f -
if ! kubectl -n sag get secret sag-redis >/dev/null 2>&1; then
  kubectl -n sag create secret generic sag-redis --from-literal=password="$(openssl rand -hex 16)"
fi

echo "== 4. Манифесты паттерна (Kustomize)"
kubectl apply -k .
kubectl -n sag rollout restart deploy >/dev/null   # подхватить пересобранные образы при повторном запуске
for d in redis sag-request-verifier sag-auth sag-authz sag-audit admin-api sag-gateway; do
  kubectl -n sag rollout status deploy/"$d" --timeout=300s
done

echo "== 5. Результат"
kubectl -n sag get pods -o wide
echo
echo "Дальше (в отдельном окне, держать открытым):"
echo "   kubectl -n sag port-forward svc/sag-gateway 8443:443"
echo "Затем:  py tools/admin_client.py all   или   py tools/demo.py"
