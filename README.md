# Harmony-rs

[![GitHub license](https://img.shields.io/github/license/Yee2/harmony-rs)](https://github.com/Yee2/harmony-rs/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Yee2/harmony-rs)](https://github.com/Yee2/harmony-rs/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/Yee2/harmony-rs)](https://github.com/Yee2/harmony-rs/issues)
[![GitHub forks](https://img.shields.io/github/forks/Yee2/harmony-rs)](https://github.com/Yee2/harmony-rs/network)

Harmony-rs 是一个 http/https 流量分流工具，能够根据请求的主机名选择是否通过代理请求还是直接请求目标服务器。

## 使用说明

```sh
harmony-rs --proxy 127.0.0.1:1080 --rule-file /etc/harmony-rs/rule.json --http-port 8080 --https--port 8443 --fwmark 8366 --enable-control-pipe --debug
```

### 参数说明

- `--proxy`：socks5 代理服务器地址，默认 127.0.0.1:1080
- `--rule-file`：域名匹配规则文件
- `--http-port`：http 服务器监听端口，默认 8080
- `--https-port`：https 服务器监听端口，默认 8443
- `--fwmark`：流量标记，标记后的流量不再次处理
- `--enable-control-pipe`：是否创建一个命名管道 /run/harmony-rs，往管道内写入的主机名，会将这个域名和所有子域名添加到代理列表
- `--debug`：打印详细日志

通过设定 `CTRL_FILE` 环境变量可以指定域名添加管道路径。

### 添加代理域名

你可以执行下面命令将 `google.com` 添加到代理列表，这同时会代理这个域名和所有子域名：

```sh
echo "google.com" > /run/harmony-rs
```

### 规则文件说明

规则文件必须是 json 格式，将域名分级保存在文件中，文件中存在的域名和这个域名的所有子域名将会通过代理服务器请求。下面配置规则表示 `google.com` 这个域名和所有子域名都会通过代理请求。

```json
{
  "com": {
    "google": null
  }
}
```

### 安装说明

```sh
sudo harmony-rs install --debug
```

执行这个命令会创建配置文件夹 `/etc/harmony-rs` 并且初始化一些配置文件，并且创建一个 systemd 服务单元路径 `/etc/systemd/system/harmony-rs.service`。

默认安装会将听端口 8080/8433，并且通过 nftables 规则将本地所有 http/https 流量转发到这两个端口，之后会根据请求主机名判断走代理还是直接请求，默认代理地址为 127.0.0.1:1080，你需要先启动一个 socks5 代理服务器并且监听这个地址。

nftables 规则文件路径为 `/etc/harmony-rs/pre.sh`，你可能需要根据自己需求修改部分参数。默认情况下会放行 fwmark 为 8366 的流量。

你可以执行以下命令启动这个服务（系统必须先安装 nftables 工具）：

```sh
systemctl enable --now harmony-rs
```

## 注意事项

1. 本软件只支持 Linux 系统，其他系统不支持
2. 需要先启动一个 socks5 代理服务器并且监听 127.0.0.1:1080 地址
3. 系统必须先安装 nftables 工具
4. nftables 规则文件路径为 /etc/harmony-rs/pre.sh，你可能需要根据自己需求修改部分参数
5. 程序运行参数位于 /etc/systemd/system/harmony-rs.service，你可能需要根据自己需求进行修改

## 开源协议

本项目采用 MIT 开源协议，详情请见 [LICENSE](https://github.com/Yee2/harmony-rs/blob/main/LICENSE) 文件。

## 免责声明

本项目仅供学习和研究使用，使用本项目产生的任何后果和责任均由使用者自行承担，与项目作者无关。使用前请仔细阅读注意事项，确保符合使用条件。