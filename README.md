# OIDC

Typecho 的 OpenID Connect 登录与账号绑定插件。

## 环境要求

- Typecho 1.2+
- PHP 扩展：`curl`、`openssl`、`json`、`session`
- 建议站点使用 HTTPS，生产环境不要把回调地址暴露在明文 HTTP 下

## 安装

```bash
cd typecho/usr/plugins
git clone https://github.com/he0119/typecho-oidc.git Oidc
```

在 Typecho 后台启用插件后，填写 OIDC 配置。

## 身份提供商配置

在身份提供商中创建一个 OIDC 客户端：

- 登录流程：Authorization Code
- PKCE：开启，`S256`
- Redirect URI：`https://你的站点/oidc/callback`
- Scope：至少包含 `openid`，常用值为 `openid email profile`
- Token Endpoint Auth Method：支持 `client_secret_basic`、`client_secret_post` 或公共客户端 `none`

## 插件配置

- OIDC 发现文档 URL：例如 `https://idp.example.com/.well-known/openid-configuration`
- OIDC 系统名称：显示在绑定页面中的名称
- Client ID：身份提供商分配的客户端 ID
- Client Secret：机密客户端填写；公共客户端可留空
- Scope：登录请求使用的作用域；插件会确保包含 `openid`

## 使用

插件会在后台添加 “OIDC 绑定” 面板。用户需要先登录 Typecho，再到该面板点击绑定按钮完成 OIDC 账号绑定。

绑定后，可以在登录页或主题中添加指向 `/oidc/login` 的入口：

```php
<a href="<?php $options->index('oidc/login'); ?>"><?php _e('单点登录'); ?></a>
```

未绑定的 OIDC 账号不能直接登录，会提示先登录 Typecho 后再绑定。

## 安全与兼容性

- 登录请求使用 `state`、`nonce` 和 PKCE，state 支持多个并发登录窗口
- ID Token 会校验签名、`iss`、`aud`、`azp`、`exp`、`iat`、`nbf` 和 `nonce`
- 当前支持 `HS256`、`RS256/RS384/RS512`、`ES256/ES384/ES512`
- UserInfo 端点可用时会校验其 `sub` 与 ID Token 一致；不可用时使用已验证的 ID Token claims
- 账号绑定使用 OIDC `iss + sub` 作为唯一身份，不依赖邮箱或用户名
- Discovery 和 JWKS 会缓存到插件目录下的 `cache/`，该目录已加入 `.gitignore`

## 常见问题

- 如果一直提示无法获取发现文档或 Token，请确认 PHP 已启用 `curl`
- 如果提示 ID Token 验证失败，请确认 PHP 已启用 `openssl`，并检查身份提供商的签名算法和 JWKS
- 如果使用公共客户端，请确认身份提供商声明并允许 `none` 认证方式
- 如果后台目录被自定义，插件会使用 Typecho 的 `adminUrl` 生成后台链接，无需额外改代码
