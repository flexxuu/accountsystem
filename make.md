# AccountSystem 项目构建指南

## 项目结构与CMake组织

本项目采用分层CMake结构，通过根目录与子目录的协作实现模块化构建：

```
account-system-cpp/
├── CMakeLists.txt        # 根目录CMake配置（主控制中心）
├── src/
│   └── CMakeLists.txt    # 源代码子目录配置（编译核心）
├── thirdlib/             # 第三方依赖库
└── make.md               # 本构建指南
```

## 根目录CMakeLists.txt 核心职责

根目录CMakeLists.txt作为项目构建的入口点，主要负责：

1. **全局配置管理**
   - 设置CMake最低版本和关键策略（如CMP0079允许子目录链接）
   - 定义项目名称和支持语言
   - 配置跨子目录的全局选项（C++标准、编译选项等）

2. **依赖统一管理**
   - 集中查找所有第三方依赖（spdlog、nlohmann_json、Poco等）
   - 强制指定本地编译的Poco库路径，避免系统库冲突
   - 为所有子目录提供一致的依赖目标

3. **项目结构组织**
   - 通过`add_subdirectory()`包含子目录（如src、thirdlib/jwt-cpp）
   - 管理输出目录和安装规则

## 子目录（src/）CMakeLists.txt 职责

src子目录专注于源代码编译，与根目录形成明确分工：

1. **源文件管理**
   - 收集并组织项目源代码文件
   - 分离库文件与可执行文件的源文件

2. **构建产物生成**
   - 创建静态库`account_system_lib`（包含所有业务逻辑）
   - 生成主可执行文件`account_system_server`

3. **依赖使用**
   - 继承并使用根目录已配置的依赖目标
   - 通过链接本地库间接使用第三方依赖

## 根目录与子目录的协作机制

1. **配置继承**：子目录自动继承根目录的全局设置（C++标准、编译选项等）

2. **依赖共享**：根目录查找的依赖目标（如`Poco::Net`）直接被子目录使用，避免重复配置

3. **目标链接**：子目录生成的库可被根目录或其他子目录链接，形成模块化构建

4. **路径管理**：通过`PROJECT_SOURCE_DIR`等变量实现根目录与子目录间的路径引用

## 构建流程详解

### 1. 准备阶段

根目录执行以下关键步骤：
- 设置C++17标准和严格编译选项
- 配置JWT库使用nlohmann_json
- 指定本地Poco库路径并禁用系统库查找

### 2. 依赖查找阶段

根目录集中查找所有依赖：
```cmake
# 根目录中统一管理依赖
find_package(spdlog REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(Poco REQUIRED COMPONENTS Net NetSSL JSON ...)
```

### 3. 子目录构建阶段

- 根目录通过`add_subdirectory(src)`触发子目录构建
- src目录编译静态库并链接根目录提供的依赖
- 生成可执行文件并链接静态库

### 4. 输出与安装

- 可执行文件输出到`build/bin`目录
- 通过RPATH配置确保运行时找到本地库
- `make install`将可执行文件和配置安装到指定位置

## 关键构建特性

### 本地库优先策略

项目强制使用本地编译的Poco库，避免系统库版本冲突：
```cmake
# 根目录中确保使用本地Poco库
find_package(Poco REQUIRED ... NO_DEFAULT_PATH NO_SYSTEM_ENVIRONMENT_PATH)
link_directories("${PROJECT_SOURCE_DIR}/thirdlib/poco.../build/lib")
```

### 模块化依赖管理

- 根目录：负责"what"（使用哪些依赖）
- 子目录：负责"how"（如何使用依赖）
- 这种分离使依赖变更只需修改根目录配置

### 跨平台兼容性

通过CMake的路径变量（如`PROJECT_SOURCE_DIR`）和条件判断，确保在不同操作系统上的一致构建体验

## 构建命令参考

```bash
# 创建构建目录并进入
mkdir build && cd build

# 生成构建文件（使用根目录CMakeLists.txt）
cmake ..

# 编译项目
make -j4

# 安装（可选）
make install
```

## 常见问题解决

### 依赖冲突
如果系统中存在多个Poco版本，根目录的`NO_DEFAULT_PATH`选项确保只使用项目指定的本地版本

### 编译错误
严格的编译选项（-Wall -Wextra -Wpedantic）可能导致警告被视为错误，需修复所有警告以确保代码质量

### 链接问题
确保所有依赖库路径正确，RPATH配置使运行时能找到本地编译的库