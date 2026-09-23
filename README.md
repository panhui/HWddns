# HWddns

华为云 DNS 管理面板。支持 A、AAAA、CNAME 记录，单次或每日定时任务、循环端口探测任务，以及立即执行、暂停、开启、编辑、删除和执行日志。

## Windows 安装版

下载并运行 [HWddns-Windows-Setup.exe](https://github.com/panhui/HWddns/releases/latest/download/HWddns-Windows-Setup.exe)。支持 64 位 Windows，无需 Docker、Python 或管理员权限。安装完成后从开始菜单启动 HWddns，程序会自动打开浏览器中的 `http://127.0.0.1:6006`，首次密码为 **Qwer1234**。

Windows 版只监听本机地址。请保持启动窗口打开，关闭窗口会停止定时任务。首次运行会在 `%LOCALAPPDATA%\HWddns` 创建配置和数据库，升级或卸载程序不会清除这些数据。可修改 `%LOCALAPPDATA%\HWddns\config.env` 中的 `ADMIN_PASSWORD`、`PORT` 和 `TZ`，然后重启程序。安装包未进行商业代码签名，Windows 可能显示“未知发布者”提示。

源码仓库的 [Windows 构建流程](https://github.com/panhui/HWddns/actions/workflows/windows-installer.yml) 会在发布标签时生成并检查安装包。

## 一键部署到 Linux

需要一台可访问 GitHub、Docker Hub 和 PyPI 的 Linux 服务器，并安装 `curl`。以 **root 用户**登录服务器后运行（无需 `sudo`）：

```bash
curl -fsSL https://raw.githubusercontent.com/panhui/HWddns/main/deploy.sh | bash
```

脚本会安装 Docker（如果缺少）、拉取本仓库、生成应用密钥并启动容器。访问 `http://服务器IP:6006`，初始管理员密码为 **Qwer1234**。首次登录后，在“云账号设置”中填写华为云 Access Key ID 和 Secret Access Key，再添加任务。如果当前不是 root 用户，请先用 `su -` 切换到 root；安装了 `sudo` 的服务器也可在命令末尾使用 `| sudo bash`。

**公网使用前请修改密码并配置 HTTPS。** 密码位于 `/opt/hwddns/.env` 的 `ADMIN_PASSWORD`；修改后在 `/opt/hwddns` 运行 `docker compose up -d --force-recreate`。可在同一文件修改 `PORT` 和 `TZ`。如果 HTTPS 由反向代理提供，可设置 `COOKIE_SECURE=1` 后重启。

重复运行部署命令会拉取最新代码并重建容器，已有 `.env` 和 Docker 数据卷不会被覆盖。卸载前请备份数据卷。

## 使用说明

1. 使用具备 DNS 公网域名查看、记录集查看、创建和修改权限的华为云 AK/SK。面板会加密保存凭据，不在页面回显。
2. **定时任务：**输入要修改的完整域名，选择记录类型（默认 A）、目标 IPv4 / IPv6 / CNAME 域名、首次执行时间及频率。时间使用 `.env` 中配置的时区，默认 `Asia/Shanghai`。
3. **探测任务：**填写要探测的域名和 TCP 端口、要修改的解析域名（可留空，与探测域名相同）、目标 IP 或 CNAME 域名，以及循环间隔（1–1440 分钟）。首次探测会在创建后开始。连续两次 TCP 连接都失败时，才会把解析切换到目标值；连接成功时不修改 DNS。
4. 任务可暂停或开启。暂停会停止自动执行；“立即执行”仍可手动运行。重新开启后，到期任务会尽快执行。单次任务按设定时间执行后结束；每日任务按同一当地时间继续执行。
5. 如果对应类型的记录不存在，会自动创建；存在则更新目标值。A 与 CNAME 互换时，如域名只有一条可安全转换的记录，面板会修改其类型。已有记录的 TTL 会保留；如果存在多条相关记录导致选择不明确，任务会报错。
6. 日志页面显示最近 200 条记录，包括执行时间、原解析值、新解析值及探测结果；删除任务会同时删除日志。

> 已有记录集的多个 IP 会被替换成任务中的一个 IP。请只为希望这样管理的解析记录创建任务。

### 关于“国内探测”

TCP 探测从**部署本面板的服务器**发出。要判断中国大陆的访问情况，需要把面板部署在中国大陆的服务器上。单台服务器只能代表该节点的连通性，不能证明全国所有运营商都可访问或不可访问。探测失败后只执行切换，不会在探测恢复时自动切回原记录。

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
