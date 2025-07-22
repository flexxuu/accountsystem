# 账户系统 (C++实现)

## 项目概述
这是一个基于C++的账户管理系统，提供用户注册、登录、邮箱验证、账户管理及OAuth2认证等功能。系统采用Poco C++库作为统一的网络库，实现了HTTP服务器、HTTP客户端和SMTP邮件发送功能，具有良好的可扩展性和可维护性。

## 技术架构

### 核心组件
1. **HTTP服务器**：基于Poco::Net::HTTPServer实现
2. **HTTP客户端**：基于Poco::Net::HTTPClientSession实现
3. **邮件服务**：基于Poco::Net::SMTPClientSession实现
4. **OAuth2服务**：支持第三方认证授权
5. **账户服务**：处理用户账户相关业务逻辑
6. **数据存储**：内存存储实现（可扩展为数据库）
7. **工具类**：提供日志、配置、安全等辅助功能

### 项目结构
```
account-system-cpp/
├── CMakeLists.txt           # 项目构建配置
├── config/                  # 配置文件目录
│   └── app.json             # 应用配置
├── src/
│   ├── controller/          # 控制器层
│   │   ├── rest_api_server.cpp  # REST API服务器实现
│   │   └── rest_api_server.h    # REST API服务器头文件
│   ├── main.cpp             # 应用入口
│   ├── model/               # 数据模型层
│   │   ├── account.cpp      # 账户模型实现
│   │   └── account.h        # 账户模型头文件
│   ├── repository/          # 数据访问层
│   │   ├── account_repository.h       # 账户仓库接口
│   │   ├── in_memory_account_repository.cpp  # 内存账户仓库实现
│   │   └── in_memory_account_repository.h    # 内存账户仓库头文件
│   ├── service/             # 服务层
│   │   ├── account_service.h          # 账户服务接口
│   │   ├── account_service_impl.cpp   # 账户服务实现
│   │   ├── account_service_impl.h     # 账户服务头文件
│   │   ├── email_service.h            # 邮件服务接口
│   │   ├── oauth2_service.h           # OAuth2服务接口
│   │   ├── oauth2_service_impl.cpp    # OAuth2服务实现
│   │   ├── oauth2_service_impl.h      # OAuth2服务头文件
│   │   ├── smtp_email_service.cpp     # SMTP邮件服务实现
│   │   └── smtp_email_service.h       # SMTP邮件服务头文件
│   └── util/                # 工具类
│       ├── config_utils.cpp # 配置工具实现
│       ├── config_utils.h   # 配置工具头文件
│       ├── http_client.cpp  # HTTP客户端实现
│       ├── http_client.h    # HTTP客户端头文件
│       ├── log.cpp          # 日志工具实现
│       ├── log.h            # 日志工具头文件
│       ├── security_utils.cpp # 安全工具实现
│       └── security_utils.h # 安全工具头文件
└── test/                    # 测试目录
    └── account_test.cpp     # 账户相关测试
```

## 核心功能实现

### 1. HTTP服务器实现
位于`rest_api_server.cpp`，使用Poco::Net::HTTPServer实现REST API服务：
- 创建ServerSocket监听指定端口
- 实现RequestHandlerFactory处理请求路由
- 为每个API端点实现对应的RequestHandler
- 支持JSON请求/响应格式
- 实现常见HTTP状态码处理

主要API端点：
- POST /api/register - 用户注册
- POST /api/verify-email - 邮箱验证
- POST /api/login - 用户登录
- GET /api/account - 获取账户信息
- PUT /api/account - 更新账户信息
- DELETE /api/account - 删除账户
- GET /oauth2/authorize - OAuth2授权
- GET /oauth2/callback - OAuth2回调

### 2. 账户服务实现
位于`account_service_impl.cpp`，提供账户管理核心功能：
- 用户注册（密码加密存储）
- 邮箱验证
- 用户登录（生成访问令牌）
- 账户信息CRUD
- 密码修改

使用安全工具类进行密码哈希和验证，使用日志工具记录关键操作。

### 3. 邮件服务实现
位于`smtp_email_service.cpp`，使用Poco::Net::SMTPClientSession实现邮件发送：
- 支持SMTP服务器配置
- 支持TLS/SSL加密
- 构建标准邮件消息
- 发送验证邮件等模板邮件

### 4. OAuth2服务实现
位于`oauth2_service_impl.cpp`，实现OAuth2认证流程：
- 支持第三方授权（通过注入的HTTP客户端）
- 处理授权码流程
- 获取和解析访问令牌
- 支持多种OAuth2提供商

### 5. HTTP客户端实现
位于`http_client.cpp`，基于Poco::Net::HTTPClientSession：
- 支持GET/POST等HTTP方法
- 支持HTTPS
- 处理JSON请求和响应
- 统一错误处理

## 依赖项
- Poco C++ Libraries (Net, Util, JSON, Crypto等模块)
- CMake (构建工具)
- C++17或更高版本

## 构建与运行
1. 安装依赖：
   ```bash
   # 安装Poco库
   # Ubuntu示例：
   sudo apt-get install libpoco-dev
   ```

2. 构建项目：
   ```bash
   mkdir build && cd build
   cmake ..
   make
   ```

3. 配置：
   修改`config/app.json`文件设置服务器端口、SMTP配置等

4. 运行：
   ```bash
   ./account-system
   ```

## 配置说明
配置文件`config/app.json`包含以下主要配置项：
- server.port: HTTP服务器端口
- server.host: 服务器绑定地址
- smtp.server: SMTP服务器地址
- smtp.port: SMTP服务器端口
- smtp.username: SMTP用户名
- smtp.password: SMTP密码
- smtp.from: 发件人邮箱
- oauth2.providers: OAuth2提供商配置
- jwt.secret: JWT令牌密钥
- jwt.expires_in: JWT令牌过期时间（秒）

## 安全考虑
- 密码使用bcrypt算法哈希存储
- 使用HTTPS加密传输（需配置SSL证书）
- 实现基本的输入验证
- 使用JWT令牌进行用户认证
- 敏感配置通过配置文件管理

## 扩展建议
1. 数据存储：实现数据库存储（如MySQL、PostgreSQL）
2. 缓存：添加Redis缓存提高性能
3. 监控：添加Prometheus指标收集
4. 日志：实现集中式日志收集
5. 测试：增加单元测试和集成测试覆盖率

## 许可证
[MIT](LICENSE)