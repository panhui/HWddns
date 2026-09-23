# HWddns

华为云 DNS 定时管理面板。支持 A/AAAA 记录、单次或每日任务、立即执行、编辑、删除，以及显示执行时间和 IP 变更的日志。

## 一键部署到 Linux

需要一台可访问 GitHub、Docker Hub 和 PyPI 的 Linux 服务器，并安装 `curl`、`git`、`python3`。在服务器上运行：

```bash
curl -fsSL https://raw.githubusercontent.com/panhui/HWddns/main/deploy.sh | sudo bash
```

脚本会安装 Docker（如果缺少）、拉取本仓库、生成应用密钥并启动容器。访问 `http://服务器IP:8080`，初始管理员密码为 **Qwer1234**。首次登录后，在“云账号设置”中填写华为云 Access Key ID 和 Secret Access Key，再添加任务。

**公网使用前请修改密码并配置 HTTPS。** 密码位于 `/opt/hwddns/.env` 的 `ADMIN_PASSWORD`；修改后在 `/opt/hwddns` 运行 `sudo docker compose up -d --force-recreate`。可在同一文件修改 `PORT` 和 `TZ`。如果 HTTPS 由反向代理提供，可设置 `COOKIE_SECURE=1` 后重启。

重复运行部署命令会拉取最新代码并重建容器，已有 `.env` 和 Docker 数据卷不会被覆盖。卸载前请备份数据卷。

## 使用说明

1. 使用具备 DNS 公网域名查看、记录集查看、创建和修改权限的华为云 AK/SK。面板会加密保存凭据，不在页面回显。
2. 输入完整域名、固定目标 IP、首次执行时间及频率。时间使用 `.env` 中配置的时区，默认 `Asia/Shanghai`。
3. 如果对应的 A/AAAA 记录不存在，会自动创建；存在则更新为输入的 IP。已有记录的 TTL 会保留；如已有多个相同域名和类型的记录集，任务会报错，避免修改错误的解析线路。
4. 单次任务按设定时间执行后结束；每日任务按同一当地时间继续执行。可随时点击“立即执行”，不会取消尚未到期的计划。日志页面显示最近 200 条记录；删除任务会同时删除日志。

> 已有记录集的多个 IP 会被替换成任务中的一个 IP。请只为希望这样管理的解析记录创建任务。

## 手动部署

```bash
git clone https://github.com/panhui/HWddns.git
cd HWddns
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'  # 填入 APP_SECRET
python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'  # 填入 DATA_KEY
docker compose up -d --build
```

查看状态：`docker compose ps`；查看运行日志：`docker compose logs -f`。

## 技术说明

应用使用 Flask、Waitress、SQLite 和华为云官方 Python SDK。服务以单个进程运行，后台每 10 秒检查到期任务。SQLite 数据库存于 Docker 数据卷，容器重建后仍保留。AK/SK 通过 Fernet 加密，密钥只存于 `.env`。不要丢失 `DATA_KEY`，否则无法解密已有凭据。

华为云接口参考：[查询公网域名](https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_62003.html)、[查询记录集](https://support.huaweicloud.com/api-dns/ListRecordSetsByZone.html)、[创建记录集](https://support.huaweicloud.com/api-dns/CreateRecordSet.html)、[修改记录集](https://support.huaweicloud.com/api-dns/UpdateRecordSet.html)。
