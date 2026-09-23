#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请切换到 root 用户后运行此脚本；如已安装 sudo，也可使用 sudo bash deploy.sh" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "缺少 curl，请先安装后重试" >&2
  exit 1
fi
missing=()
for command in git python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    missing+=("$command")
  fi
done
if ((${#missing[@]})); then
  echo "正在安装 ${missing[*]} ..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y "${missing[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${missing[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${missing[@]}"
  else
    echo "无法自动安装 ${missing[*]}，请手动安装后重试" >&2
    exit 1
  fi
fi

INSTALL_DIR="${INSTALL_DIR:-/opt/hwddns}"
REPO_URL="https://github.com/panhui/HWddns.git"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" pull --ff-only
elif [[ -e "$INSTALL_DIR" ]]; then
  echo "$INSTALL_DIR 已存在且不是 HWddns 仓库，请设置其他 INSTALL_DIR" >&2
  exit 1
else
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "正在安装 Docker ..."
  curl -fsSL https://get.docker.com | sh
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose 插件不可用，请安装后重新运行部署脚本" >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now docker
fi

cd "$INSTALL_DIR"
if [[ ! -f .env ]]; then
  APP_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  DATA_KEY="$(python3 -c 'import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')"
  umask 077
  cat > .env <<EOF
ADMIN_PASSWORD=Qwer1234
APP_SECRET=$APP_SECRET
DATA_KEY=$DATA_KEY
TZ=Asia/Shanghai
PORT=6006
EOF
fi
docker compose up -d --build
echo
echo "HWddns 已启动。访问 http://服务器IP:6006 ，管理员密码：Qwer1234"
echo "配置文件：$INSTALL_DIR/.env（请在公网开放前更改管理员密码并配置 HTTPS）"
