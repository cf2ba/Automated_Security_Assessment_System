# 示例目标项目（故意包含漏洞）

这是一个用于演示自动化安全评估系统的 Flask 应用，**故意**包含以下漏洞，请勿在生产环境使用：

| 位置 | 漏洞类型 | 说明 |
|---|---|---|
| `/login` | SQL 注入 | 用户名、密码直接拼接进 SQL 语句 |
| `/ping` | 命令注入 | `host` 参数直接拼接进 `os.popen` |
| `/search` | 反射型 XSS | `q` 参数未转义直接输出 HTML |
| `/download` | 路径穿越 | `file` 参数未限制目录 |
| `/admin` | 硬编码密钥 / 弱鉴权 | 固定 `token=admin`，`SECRET_KEY` 硬编码 |
| `app.py` | 硬编码密钥 | `SECRET_KEY`、`ADMIN_TOKEN` 写在源码中 |

## 运行方式

```bash
pip install -r requirements.txt
python app.py
```

默认监听 `0.0.0.0:5000`。评估系统会把它只读挂载到隔离容器的 `/src` 并在容器内启动。
