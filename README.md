# PHP Serializable var_hash UAF → RCE（复现 + 适配版 EXP）

PHP `unserialize()` 中 `Serializable` 接口的 var_hash 使用后释放（UAF），可至远程/本地命令执行。
原始研究：[calif.io/research/php-uaf](https://calif.io/research/php-uaf)（MADBugs，AI-Discovered），原始 PoC：[califio/publications](https://github.com/califio/publications/tree/main/MADBugs/php)。本仓库为**独立复现 + 特定构建适配 + 实测验证记录**。

> ⚠️ 仅用于授权测试与防御研究。remote 利用需目标存在 `unserialize()` 入口 + 特定形态 Serializable gadget；本地利用常用于 `disable_functions` 突破。

## 根因（一句话）

`Zend/zend_interfaces.c` 的 `zend_user_unserialize()` 派发 `Serializable::unserialize()` 用户代码时**缺失 `BG(serialize_lock)++`**（其余 `__wakeup`/`__unserialize`/`__destruct` 派发点均有），gadget 内嵌套 `unserialize()` 复用外层 var_hash；随后对内层对象写第 9 个属性触发属性表 8→16 扩容释放旧 arData，外层 `R:N;` 反向引用悬空 → UAF。影响 PHP 5.1（2005）至今全部版本。

## 实测验证记录（2026-10-21）

| 项目 | 环境 | 结果 |
|---|---|---|
| UAF 实锤 | php-src 8.4.4 源码编译（ASan + USE_ZEND_ALLOC=0） | `heap-use-after-free`，free/UAF 栈与机制逐行吻合（见 `asan_uaf_evidence.txt`） |
| 完整 RCE | Ubuntu 24.04 官方 apt php8.3.6（NTS x86_64） | Phase 1→8 全通，伪造 Closure 调 `zif_system`，`uid=1000` + uname |
| disable_functions 绕过 | 同上，七函数全禁（system/exec/shell_exec/passthru/proc_open/popen/pcntl_exec） | 走 standard 模块**静态函数表**取 `zif_system`，10/10 命中 |
| 无禁用对照 | 同上 | 5/5 命中 |

## 用法

```bash
# EXP（命令改文件顶部 CMD 常量）
php exp.php

# 最小 UAF 触发器（需 ASan 构建 + USE_ZEND_ALLOC=0）
USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 ./php uaf_trigger.php 4

# 换构建适配：用 addrs.c 探针实测偏移（phpize 编译后 get_addrs/get_modinfo）
phpize && ./configure --enable-addrs && make && php -d extension=modules/addrs.so -r '$c=function(){}; var_dump(get_addrs($c), get_modinfo());'
```

## 换构建适配点（php8.3.6 实测值）

| 参数 | calif 原版 | 本构建实测 | 探针依据 |
|---|---|---|---|
| `zend_internal_function.handler` | 0x58 | **0x48** | offsetof 探针（8.1 为 0x38，随构建漂移） |
| `zend_internal_function.module` | 0x60 | **0x50** | 同上 |
| `FUNC_ENTRY_SIZE` | 0x30 | **0x20** | `sizeof(zend_function_entry)` |
| EG 定位 | 仅正向 delta | **负向扫描 + symbol_table(EG+0x130) 指纹交叉验证**（本构建 EG = closure_handlers − 0x1F20，原版会先命中假阳性指纹） | `get_addrs()` |

`EG.function_table` @ +0x1b0、`EG.symbol_table` @ +0x130 在 8.1–8.5 实测稳定。

## 附：事件核查结论

2026-10 泄露事件（"php2shell"）期间流传的 jackalsyn.com `session.upload_progress UAF` 分析为**错误分析**（引用的 CVE-2026-109618/619 在 NVD/cveawg/cvelistV5 均不存在；其 PoC 在 ASan-FPM 上零报错；session.c 引用计数链闭环）。详见 `复现报告.md` 第一节。CVSS 评估：远程现实场景 ≈ 7.4（AC:H），流传的 9.2/9.8 忽略了 gadget 前提。

## 文件清单

| 文件 | 说明 |
|---|---|
| `exp.php` | 正式 EXP（calif PoC + 本构建 5 处适配），一键运行 |
| `uaf_trigger.php` | 25 行最小 UAF 触发器（ASan 证据用） |
| `addrs.c` | EG/handler/模块表偏移探针扩展（换构建适配第一步） |
| `asan_uaf_evidence.txt` | ASan 报告原件 |
| `复现报告.md` | 完整复现报告（含 jackalsyn 帖证伪四证据、阴性对照、绕过实测） |
