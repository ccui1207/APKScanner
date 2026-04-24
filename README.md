# APKScanner

APKScanner 是一个面向 Android APK 的静态安全扫描工具，支持单 APK 分析、批量扫描、结果汇总以及按漏洞向量反查命中的 APK。

## 功能特性

- 支持单个 APK 的静态安全扫描
- 支持目录级批量扫描
- 支持生成批量结果的 summary 汇总表
- 支持按漏洞向量查询命中的 APK
- 支持将分析结果持久化到 MongoDB
- 支持常见 Android 安全检测项，例如：
  - `DEBUGGABLE`
  - `COMMAND`
  - `COMMAND_SU`
  - `HACKER_BASE64_STRING_DECODE`
  - `SSL_CN2`
  - `SSL_URLS_NOT_IN_HTTPS`
  - `WEBVIEW_RCE`
  - `STRANDHOGG_2`

## 项目结构

```bash
.
├── apk_scanner.py              # 单 APK 扫描入口
├── apk_massive_analysis.py     # 批量扫描入口
├── apk_report_summary.py       # 汇总报表
├── apk_report_by_vector.py     # 按漏洞向量查询 APK
├── apkscanner-db.cfg           # MongoDB 配置文件
├── vectors/                    # 漏洞向量实现
├── writer.py                   # 报告输出
├── persist.py                  # 结果持久化
├── engines.py                  # 扫描引擎相关逻辑
├── staticDVM.py                # 静态分析支持逻辑
├── helper_functions.py
├── utils.py
├── constants.py
├── vector_base.py
├── bash_scripts/
├── test_applications/          # 测试 APK 样本
└── requirements.txt
```
## 运行环境

建议环境：

* Ubuntu 22.04 或类似 Linux 环境
* Python 3.10+
* MongoDB 8.x
* Git

## 安装方式

### 1. 克隆项目

```bash
git clone https://github.com/ccui1207/Apk_Check.git
cd Apk_Check
```

### 2. 创建并激活虚拟环境

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

## MongoDB 配置

批量分析、summary 汇总和按向量查询依赖 MongoDB。

默认配置文件：

```bash
apkscanner-db.cfg
```

启动 MongoDB：

```bash
sudo systemctl start mongod
sudo systemctl status mongod
```

如果状态显示为 `active (running)`，说明 MongoDB 已正常运行。

## 使用方法

### 1. 单 APK 扫描

```bash
python apk_scanner.py -f /实际/apk/路径/app.apk -o Reports
```

示例：

```bash
python apk_scanner.py -f ./test_applications/runtime-exec-app-debug.apk -o Reports
```

扫描完成后，会在 `Reports/` 目录下生成对应 APK 的详细文本报告。

---

### 2. 批量扫描

先准备输入目录：

```bash
mkdir -p massive_input
cp test_applications/*.apk massive_input/
```

再执行批量分析：

```bash
python apk_massive_analysis.py \
  -b 20260424 \
  -t DemoRun \
  -d ./massive_input \
  -o ./Massive_Analysis_Reports \
  -i
```

参数说明：

* `-b`：分析批次号
* `-t`：分析标签
* `-d`：待扫描 APK 目录
* `-o`：报告输出目录
* `-i`：忽略重复扫描

---

### 3. 生成汇总报表

```bash
python apk_report_summary.py -m massive -b 20260424 -t DemoRun
```

summary 表会按漏洞向量统计本轮批量分析的结果，包括：

* `Critical`
* `Warning`
* `Notice`
* `Info`
* `Total`

适合快速查看整批 APK 的风险分布情况。

---

### 4. 按漏洞向量查询 APK

查询命令执行相关命中的 APK：

```bash
python apk_report_by_vector.py -v COMMAND -l Critical -m massive -b 20260424 -t DemoRun
```

查询 debuggable 命中的 APK：

```bash
python apk_report_by_vector.py -v DEBUGGABLE -l Critical -m massive -b 20260424 -t DemoRun
```

查询 Base64 相关命中的 APK：

```bash
python apk_report_by_vector.py -v HACKER_BASE64_STRING_DECODE -l Critical -m massive -b 20260424 -t DemoRun
```

查询明文 HTTP URL 命中的 APK：

```bash
python apk_report_by_vector.py -v SSL_URLS_NOT_IN_HTTPS -l Critical -m massive -b 20260424 -t DemoRun
```

## 输出说明

### 单 APK 报告

输出到 `Reports/` 目录，包含：

* APK 基本信息
* 风险等级（Critical / Warning / Notice / Info）
* 命中的漏洞向量
* 对应类名、方法名和调用位置

### summary 汇总表

按漏洞向量统计一批 APK 的扫描结果，适合看总体情况。

### by-vector 查询结果

按某个漏洞向量列出所有命中的 APK，适合做进一步人工复核。

## 推荐使用流程

```bash
source venv/bin/activate

# 单 APK 扫描
python apk_scanner.py -f ./test_applications/runtime-exec-app-debug.apk -o Reports

# 批量扫描
mkdir -p massive_input
cp test_applications/*.apk massive_input/

python apk_massive_analysis.py \
  -b 20260424 \
  -t DemoRun \
  -d ./massive_input \
  -o ./Massive_Analysis_Reports \
  -i

# 查看汇总表
python apk_report_summary.py -m massive -b 20260424 -t DemoRun

# 按向量查询
python apk_report_by_vector.py -v COMMAND -l Critical -m massive -b 20260424 -t DemoRun
```

## 常见问题

### 1. 提示 `apk_file_not_exist`

说明 `-f` 后面的 APK 路径写错了，请替换成真实路径。

### 2. 出现 `No Magic library was found on your system.`

这通常只是提示，不一定会阻塞主流程。如果扫描、summary、by-vector 都正常完成，可以先忽略。

### 3. 出现 `Requested API level ... returning API level 28 instead.`

这一般是兼容性提示，不一定影响测试样本扫描。

### 4. summary 统计数量异常变大

通常是因为相同 APK 使用相同的 `build + tag` 被重复入库导致。建议：

* 每次批量分析使用新的 `-t`
* 或加 `-i` 参数避免重复扫描


## 当前状态

当前版本已经验证支持以下完整流程：

* 单 APK 扫描
* 批量扫描
* summary 汇总
* by-vector 查询

并且已经完成旧引用清理，不再依赖早期脚本名和旧配置名。

## 说明

本工具更适合用于 APK 静态安全初筛、批量样本统计和人工复核前的预分析。
部分 `Warning` 和 `Notice` 项可能包含第三方库噪声，最终结论仍建议结合具体代码位置人工确认。
