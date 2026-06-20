# 基于商密算法的口令认证增强系统设计与实现

## 1. 项目概述

本项目围绕“服务器不接触、不保存用户明文口令或口令等价物”这一目标，设计并实现了一个基于 SM2/SM3 的口令认证增强系统。系统分为注册和认证两个阶段：注册时，客户端以“用户名 + 口令 + 随机盐值”为输入派生 SM2 私钥，并将对应公钥与盐值上传至服务端；认证时，服务端发放一次性的 `Session_ID + Nonce` 挑战，客户端重新派生私钥后构造鉴别 Token 并完成数字签名，服务端仅凭数据库中的公钥完成验签。整体采用 Go 实现，包含真实 HTTP 网络交互、SQLite 用户存储、GUI 客户端以及自动化测试，重点验证重放防护、错误口令拒绝、挑战过期、并发消费与接口健壮性等安全语义。

## 2. 设计亮点

- 口令只在客户端短暂存在，服务端仅保存 `用户名 + 盐值 + SM2 公钥`，避免传统“口令哈希被拖库后直接离线爆破”的直接风险暴露面。
- 认证流程采用挑战-应答机制，Token 同时绑定用户名、会话编号和随机挑战，避免历史签名被直接重放。
- `Session_ID` 采用原子消费语义，确保同一挑战在并发场景下至多成功一次，修复了常见的重放窗口问题。
- `challenge` 和 `register` 接口做了抗枚举处理，不通过响应码直接泄露用户是否存在。
- 服务端加入固定窗口限流，客户端对口令字节做显式覆写，兼顾基础 DoS 防护与敏感数据最小驻留。

## 3. 总体结构与设计细节

### 3.1 系统架构

```text
+-----------------------+            HTTP/JSON            +-----------------------+
| GUI Client            | <----------------------------> | Auth Server           |
|                       |                                |                       |
| - 用户输入            |                                | - /api/register       |
| - 注册/登录按钮       |                                | - /api/auth/challenge |
| - 状态展示            |                                | - /api/auth/verify    |
+-----------+-----------+                                +-----------+-----------+
            |                                                            |
            v                                                            v
+-----------------------+                                +-----------------------+
| Client Crypto         |                                | Storage               |
|                       |                                |                       |
| - SM3 私钥派生        |                                | - SQLite 用户表       |
| - SM2 签名            |                                | - 内存会话表          |
| - 口令擦除            |                                | - 限流状态            |
+-----------------------+                                +-----------------------+
```

### 3.2 认证流程

```text
1. 注册
   Client: 用户名 + 口令 + salt -> 派生 SM2 私钥 -> 生成公钥
   Client -> Server: username, salt, public_key
   Server: 保存 username, salt, public_key

2. 认证
   Client -> Server: 请求 challenge(username)
   Server -> Client: session_id, nonce, salt
   Client: 用 username + 口令 + salt 重新派生私钥
   Client: 组装 Token(version, username, session_id, nonce) 并签名
   Client -> Server: username, session_id, token, signature
   Server: 读取公钥验签，成功后原子消费 session_id
```

### 3.3 模块划分

```text
cmd/
  server/              服务端入口
  client-gui/          GUI 客户端入口
internal/
  api/                 HTTP 接口、限流、请求校验
  crypto/              SM3 派生、SM2 签名验签
  protocol/            鉴别 Token 的规范化编码
  store/               SQLite 用户存储、内存会话存储
  gui/                 Fyne 图形界面与客户端 API 调用
tests/                 集成测试与认证流程测试
scripts/               启动脚本与测试脚本
```

### 3.4 关键实现说明

- `internal/crypto`
  负责将 `用户名 + 口令 + 盐值` 通过 SM3 确定性派生为 SM2 私钥，并处理极小概率的非法私钥边界。
- `internal/protocol`
  使用长度前缀的规范化编码构造 Token，避免 JSON 字段顺序变化导致验签歧义。
- `internal/api`
  实现注册、挑战、验签三类接口；统一做参数校验、尾随 JSON 拒绝、限流与通用错误返回。
- `internal/store`
  使用 SQLite 保存长期用户公钥材料，使用内存会话表保存短期挑战，并提供 `Consume` 原子消费接口。
- `internal/gui`
  提供图形化注册/登录界面，便于展示真实客户端交互流程。

## 4. 测试方法

项目包含单元测试和集成测试，重点覆盖以下场景：

- 正常注册、挑战、登录成功。
- 错误口令登录失败。
- 篡改 `nonce` 或 Token 后认证失败。
- 挑战过期后认证失败。
- 同一 challenge 重放失败。
- 并发 `verify` 下同一挑战最多成功一次。
- 重复注册和不存在用户 challenge 不泄露账户存在性。
- 频繁请求触发限流。

执行方式：

```bash
go test ./...
./scripts/test_all.sh
./scripts/test_e2e.sh
```

## 5. 使用方法

### 5.1 环境要求

- Go `1.25.8`
- Linux 图形环境
- Fyne 依赖的桌面图形库已安装

### 5.2 启动服务端

```bash
./scripts/run_server.sh
```

默认监听地址为 `:8080`。

### 5.3 启动客户端

```bash
./scripts/run_client.sh
```

GUI 默认连接 `http://127.0.0.1:8080`，输入用户名和口令后可分别执行注册与登录。

### 5.4 可用接口

- `GET /healthz`
- `POST /api/register`
- `POST /api/auth/challenge`
- `POST /api/auth/verify`

## 6. 未来展望

- 将当前基于 SM3 的确定性派生扩展为可调迭代次数的抗爆破 KDF。
- 在认证握手中加入临时 DH 参数，协商具备前向安全性的会话密钥。
- 将内存会话表替换为支持原子操作和过期控制的分布式存储，提升并发与部署能力。
- 增加审计日志、TLS 传输保护以及更严格的敏感内存擦除机制，进一步补齐工程级安全能力。
