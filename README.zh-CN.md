# anytls-zig

面向 OpenWrt 与嵌入式 Linux 的轻量 AnyTLS 客户端。本地 SOCKS5 接入，对外使用
AnyTLS 协议 v2 与 TLS 1.3，不依赖 Go/JVM/运行时，不使用垃圾回收，最终产物是
单个静态链接 ELF。配置可来自命令行参数、TOML 文件，或 OpenWrt 上的 UCI/LuCI。

```
SOCKS5 客户端 ──► stream（多路复用）──► session ──► TLS 1.3 ──► AnyTLS 服务端 ──► 目标
```

[English README](README.md)

## 兼容性依据

线上格式来自参考实现
[`anytls/anytls-go`](https://github.com/anytls/anytls-go) 的 `anytls/0.0.13`
（协议版本 2）及其 `docs/protocol.md`：

| 项目 | 格式 |
|---|---|
| 认证 | `sha256(password)` 32 字节，padding0 长度 `u16 BE`，padding0 数据 |
| 帧 | `cmd u8` + `streamId u32 BE` + `dataLen u16 BE` + data |
| 命令 | `0 waste, 1 SYN, 2 PSH, 3 FIN, 4 Settings, 5 Alert, 6 UpdatePaddingScheme, 7 SYNACK, 8 HeartRequest, 9 HeartResponse, 10 ServerSettings` |
| Settings | `v=2\nclient=anytls-zig/0.1.0\npadding-md5=<方案的 md5>` |
| 目标地址 | SOCKS5 地址格式：`ATYP | addr | port BE` |
| 填充 | 默认方案 `stop=8 ...` 与参考实现逐字节一致；默认方案的 `padding-md5` 为 `75cff2ad89aadf5e257059ee571ebe11` |

与参考客户端一致的行为：

* 会话多路复用与空闲会话复用（优先复用最新会话，默认 30 秒空闲超时、保留 5 个
  热会话）；
* 填充包 0–7，包含拆包写、`cmdWaste` 填充以及 `c` 检查标记；
* `cmdSettings` 与首个 `SYN`、目标地址合并在一次 TLS 写入中发送（即包 1），与
  参考实现一致；
* `cmdSYNACK` 带错误时关闭对应 stream；v2 会话在 3 秒内未收到 SYNACK 则关闭该
  卡住的会话；
* 收到 `cmdHeartRequest` 回复 `cmdHeartResponse`；
* `cmdUpdatePaddingScheme` 只影响**之后新建**的会话（每个会话持有创建时的方案
  快照，与协议文档一致）；
* 本端写方向关闭时发送 `cmdFIN`；收到对端 `FIN` 时产生 EOF，且不回复 FIN，符合
  协议规定。

## TLS

TLS 由 Zig 标准库提供（`std.crypto.tls.Client`），即进程内 TLS 1.3 实现，不依赖
C 语言 TLS 库：

* 与现代服务端协商 TLS 1.3（实测协商结果为 `tls_1_3`），TLS 1.2 仅作为回退；
* 服务器证书链通过 CA bundle 校验，主机名/SNI 同样校验（不匹配时报
  `CertificateHostMismatch`）；
* CA bundle 来自 `--ca` 或系统路径（`/etc/ssl/certs/ca-certificates.crt` 等）；
  OpenWrt 上请安装 `ca-bundle`；
* `--insecure` 是唯一关闭校验的方式，并且启动时会打印警告。

曾评估 wolfSSL 与 Mbed TLS：它们需要额外的 C 构建、增加约 100–200 KB 代码，而
AnyTLS 组帧工作仍然要自己实现；Zig 自带客户端已经完成完整的证书链与主机名校验，
引入 C TLS 库只会增加体积和构建复杂度。`src/tls.zig` 是很薄的封装
（dial/read/write/close），如果将来某个服务端使用了标准库不支持的证书算法，替换
为 wolfSSL 的范围是可控的。

## 资源模型

* 分配器：`std.heap.c_allocator`（musl malloc，线程安全）；不使用 GC。
* 每个会话约 101 KB 堆内存（4 个 16 645 字节的 TLS 缓冲区、20 KB 的帧/填充
  暂存区、16 KB 的 PSH 读缓冲区）。会话会被池化复用，而不是每个请求新建。
* 每个 stream 一个 16 KB 有界环形缓冲区，向会话读线程施加背压（不做无界缓冲）。
* 线程：每个会话一个读线程（128 KB 栈），每个本地连接一个处理线程（512 KB，
  负责 TLS 握手与本地→远端方向），每个 stream 一个泵线程（96 KB），另有一个
  清理线程（64 KB）。栈是地址空间预留，RSS 随实际使用增长。
* 每块内存都有唯一所有者；stream 使用引用计数（创建者 + 会话映射 + 中继线程），
  session 使用引用计数（映射 + 读线程 + streams），最后一个引用释放后才关闭
  socket，因此迟到的写线程不会写到被复用的文件描述符上。

## 构建

需要 Zig **0.15.1**。

`zig build` 默认生成 **静态 musl** 的本机二进制。这与部署目标一致，同时避开
Zig 0.15.1 原生 glibc 线程启动在部分主机上的 panic。需要时可用
`-Dtarget=`/`-Dcpu=` 覆盖。

本机测试构建：

```sh
zig build -Doptimize=Debug
./zig-out/bin/anytls-zig --help
```

静态交叉编译：

```sh
zig build -Doptimize=ReleaseSmall -Dtarget=aarch64-linux-musl
zig build -Doptimize=ReleaseSmall -Dtarget=arm-linux-musleabihf -Dcpu=cortex_a7-neon
zig build -Doptimize=ReleaseSmall -Dtarget=mipsel-linux-musleabi -Dcpu=mips32r2

file zig-out/bin/anytls-zig
readelf -h -l zig-out/bin/anytls-zig   # 无 INTERP、无 NEEDED
```

说明：

* 选择与目标 ABI 匹配的 triple（`aarch64-linux-musl`、`arm-linux-musleabihf`、
  `mipsel-linux-musleabi` 等）。硬浮点用户态需要 `…eabihf`，软浮点需要 `…eabi`。
  `-Dcpu` 用来选择基线（`cortex_a7`、`mips32r2` 等），可以省略。
* 首次为新目标构建时会从源码编译 musl，在性能较弱的机器上可能需要数分钟；之后
  会命中缓存。
* 等价的直接命令：
  `zig build-exe src/main.zig -lc -OReleaseSmall -target <triple> -fstrip`
* 32 位 ARM 构建面向 ARMv7-A + VFPv4，关闭 NEON（`-Dcpu=cortex_a7-neon`），可运行在
  任意 ARMv7 硬浮点目标上；打包时同时生成 `arm_cortex-a7` 和
  `arm_cortex-a7_neon-vfpv4` 两个标签。
* CI 每种架构产出两个构建——`ReleaseSmall`（无后缀）和 `ReleaseFast`
  （`-fast`）——x86-64 只发布 `ReleaseFast`。体积（Zig 0.15.2，已 strip）：

  | 架构 | `ReleaseSmall` | `ReleaseFast` |
  |---|---:|---:|
  | aarch64（fast 用 `+aes+sha2`） | 372 KB | 712 KB |
  | armv7 | 581 KB | 997 KB |
  | mips / mipsel | 841 KB | 1.68 MB |
  | x86-64（fast 用 `+aes+pclmul+avx`） | – | 788 KB |

  flash 紧张的路由器用 small；QEMU 下 fast 约快 1.2 倍（MIPS）到 1.5 倍
  （ARMv7），x86-64 上约快 3 倍。实测见
  [docs/bench-aarch64.md](docs/bench-aarch64.md)。
* `scripts/make-apk.sh` 可把已构建的二进制打成 OpenWrt apk；CI 会为所有目标生成。
* `scripts/make-luci-apk.sh` 生成与架构无关的 `luci-app-anytls-zig` apk，并在打包时
  把 `po/zh_Hans` 编译成 `.lmo`（与 LuCI 官方 `po2lmo` 输出逐字节一致）。
* 两个打包脚本都需要 apk-tools 3（`apk mkpkg`）：设置
  `APK=/path/to/apk.static` 或保证 `apk` 在 `PATH` 中。产物是 ADB v3 格式，
  即 OpenWrt snapshot / 25.x 使用的格式。

## 配置

配置优先级为 **命令行 > TOML 文件 > 内置默认值**。

### TOML 文件

```sh
anytls-zig -c /etc/anytls-zig/config.toml
```

只支持一个刻意做小的 TOML 子集：注释、`[server]`/`[listen]`/`[session]`/`[log]`
表、基本/字面字符串、整数与布尔值。未知键和类型错误会带着“文件:行号”报错，
不会被静默忽略。完整示例见 [config/anytls-zig.toml](config/anytls-zig.toml)：

```toml
[listen]
address = "127.0.0.1:1080"

[server]
address = "example.com:443"
sni = "example.com"
password = "your-password"
ca = "/etc/ssl/certs/ca-certificates.crt"
insecure = false
connect_timeout = 10

[session]
min_idle = 5
idle_timeout = 30
max_streams = 128
half_close_wait = 3

[log]
level = "info"
```

### 命令行

```
anytls-zig -l 127.0.0.1:1080 \
           -s example.com:443 \
           --sni example.com \
           -p 'your-password' \
           --ca /etc/ssl/certs/ca-certificates.crt
```

或者使用 URI：

```
anytls-zig -s 'anytls://password@example.com:443?sni=example.com'
```

参数：`-l/--listen`、`-s/--server`、`-p/--password`、`--sni`、`--ca`、
`--insecure`、`-m/--min-idle`、`--idle-timeout`、`--connect-timeout`、
`--max-streams`、`--half-close-wait`、`--log-level`、`-V`、`-h`。

启动时密码会被 SHA-256 哈希，内存中只保留哈希值，且从不写入日志。使用环境变量
`ANYTLS_PASSWORD` 可以避免密码出现在进程参数中；若密码来自 TOML 或 UCI 文件，
请确保该文件仅 root 可读。

## OpenWrt 部署

1. 安装客户端，二选一：

```sh
# CI 构建的 apk（未签名：用镜像信任的密钥签名，或允许未签名安装）
apk add --allow-untrusted anytls-zig_<version>_<arch>.apk
```

   `<arch>` 取 `cat /etc/apk/arch` 的值（例如 `arm_cortex-a7`、
   `arm_cortex-a7_neon-vfpv4`、`mipsel_24kc`）。注意 `apk --print-arch` 可能显示
   apk 二进制编译时的默认架构，与 `/etc/apk/arch` 不一致；安装时以该文件为准。

   如果需要 Web 界面，再安装与架构无关的 LuCI 包：

```sh
apk add --allow-untrusted luci-app-anytls-zig_<version>_noarch.apk
```

   两者都是 apk-tools 3 的 ADB v3 包（OpenWrt snapshot / 25.x）。OpenWrt 24.10
   及更早版本使用 opkg：可直接安装二进制，或用 OpenWrt SDK 配合 `openwrt/`、
   `openwrt/luci/` 构建 .ipk。包未签名：用镜像信任的密钥签名，或使用
   `--allow-untrusted`。也可以直接把 `zig-out/bin/anytls-zig` 复制到
   `/usr/bin/anytls-zig`，再把 `openwrt/files/` 中的文件放到对应位置。

2. 安装 CA 证书包：`opkg install ca-bundle`（或 `apk add ca-bundle`）。
3. 设置密码并保护配置文件：

```sh
uci set anytls-zig.main.password='your-password'
uci commit anytls-zig
chmod 600 /etc/config/anytls-zig
```

4. 启动服务：

```sh
/etc/init.d/anytls-zig enable
/etc/init.d/anytls-zig start
logread -e anytls-zig
```

5. 让局域网客户端指向 `192.168.1.1:1080`（SOCKS5），或把它作为透明代理工具的
   上游。默认的 `127.0.0.1:1080` 只监听回环地址。

`openwrt/` 下的软件包 Makefile 假定仓库被放在 `package/anytls-zig/`，并通过
`ZIG=/path/to/zig` 指定编译器；Zig 不属于 OpenWrt buildroot，需由构建机提供。
请按目标设置 `ZIG_TARGET`/`ZIG_CPU`（见 Makefile 顶部注释）。

### LuCI

`openwrt/luci/luci-app-anytls-zig/` 是上述 UCI 配置的 LuCI 应用：

* 放到 `feeds/luci/applications/luci-app-anytls-zig/`（或
  `package/luci-app-anytls-zig/`，并调整 `luci.mk` 的 include 路径）；
* 在 `make menuconfig` 中选中 `luci-app-anytls-zig`（依赖 `anytls-zig`）；
* 页面位于 **服务 → AnyTLS Zig**，提供英文与简体中文（LuCI 语言代码 `zh-cn`，
  词条来自 `po/zh_Hans`）。

CI 会生成 `luci-app-anytls-zig_<version>_noarch.apk`；翻译在打包时编译为
`/usr/lib/lua/luci/i18n/anytls-zig.zh-cn.lmo`，不需要额外的 i18n 包。LuCI 按运行时
语言代码（`zh-cn`）查找词条，所以文件名不是 `zh_Hans.lmo`。

表单覆盖监听地址、服务器/SNI、密码、CA 证书、校验开关、超时、会话池、stream
上限、PAC 选项和日志级别。密码保存在 `/etc/config/anytls-zig`，请把该文件权限
设为 600。`scripts/check-luci-i18n.py` 会检查每条界面字符串都有翻译。

### PAC 文件

打开 `pac_enabled` 后服务会生成 `/www/anytls-zig.pac`，uhttpd 通过
`http://<LAN-IP>/anytls-zig.pac` 提供。代理地址由 LAN 地址和 `listen` 里的
SOCKS5 端口自动生成；要让局域网设备使用，请把 `listen` 设为 `0.0.0.0:1080`
（监听地址是具体 IP 时直接使用该 IP）。URL 同时写入
`/tmp/anytls-zig.pac.url`。

本地/私网地址和 `/usr/share/anytls-zig/china-domains.txt` 中的域名走直连
（内置常见中国站点，可自行编辑），`pac_bypass` 列表中的域名同样直连；其余流量
走 SOCKS5 代理，并以 DIRECT 作为回退。服务启动/重载时重新生成。

```sh
uci set anytls-zig.main.listen='0.0.0.0:1080'
uci set anytls-zig.main.pac_enabled='1'
uci add_list anytls-zig.main.pac_bypass='example.cn'
uci commit anytls-zig
/etc/init.d/anytls-zig restart
```

内置列表只是常见站点样本，不是完整的中国域名列表；每行一个后缀。直接修改
安装目录里的文件可能在升级时被覆盖，长期追加请用 `pac_bypass`。

LuCI 里会显示 PAC 地址（按你打开 LuCI 时使用的地址生成）。若返回 404，先确认
服务在运行（`logread -e anytls-zig`）且 `/www/anytls-zig.pac` 存在；生成脚本位于
`/usr/libexec/anytls-zig/pac`。注意 v0.1.4 的 apk 漏装了生成脚本和域名列表，
请确认安装的包确实包含这两个文件。

## 体积

在 32 位 MIPS 构建（`mipsel-linux-musleabi`、`-mcpu=mips32r2`）、静态 musl、
开启 `strip` 下实测：

| 构建 | ELF 大小 |
|---|---|
| Debug，保留符号 | 7 897 848 B |
| Debug，strip | 3 674 932 B |
| ReleaseSafe，strip | 1 580 324 B |
| ReleaseFast，strip | 1 688 276 B |
| **ReleaseSmall，strip，无 unwind 表** | **844 492 B** |
| ReleaseSmall，aarch64-linux-musl（参考） | 372 168 B |
| ReleaseSmall，aarch64 + `aes+sha2` | 356 408 B |
| ReleaseSmall，armv7 硬浮点（`arm-linux-musleabihf`、`cortex_a7`） | 516 580 B |

该二进制为 `ELF32 LSB, MIPS32r2, o32, 软浮点, 静态链接`，没有 `INTERP`，
也没有动态段。段分布：`.text` 737 604 B、`.rodata` 49 628 B、`.pdr` 42 272 B
（保留以便 MIPS 上的 panic 回溯可读，非装载段）、`.bss` 5 KB。
`-fno-unwind-tables` 节省约 25 KB；`ReleaseSmall` 的体积约为
`ReleaseSafe`/`ReleaseFast` 的一半。

运行时内存（aarch64 release 构建，读取 `/proc/<pid>/status`）：空闲时 420 KB
RSS、2 个线程；10 个并发会话加 10 个活跃 stream 时约 2.9 MB（每连接约 240 KB，
主要是 TLS 缓冲区和线程栈）；stream 关闭且空闲会话过期后回落到约 500 KB。
`.bss` 仅 5 KB，是因为会话缓冲区按需分配。

## 已执行的测试

所有测试均针对从源码构建的参考服务端 `anytls-go 0.0.13`，使用本地生成的 CA 与
`localhost` 证书，以及本地 HTTP 源站。

| 测试 | 结果 |
|---|---|
| 单元测试：帧编解码、SOCKS 地址编码、UDP/UoT 组帧、默认方案 MD5（`75cff2ad…`）、填充解析与尺寸生成、settings、有界管道、TOML 解析、配置优先级、随附示例配置 | 18/18 通过 |
| TOML 配置端到端：仅用配置文件启动、命令行覆盖、TOML 中的密码、重复键/未知键/类型/表头错误诊断 | 通过 |
| LuCI 翻译覆盖（`scripts/check-luci-i18n.py`） | 35/35 条已翻译 |
| TLS 1.3 + 证书链 + SNI | 协商为 `tls_1_3`；错误 SNI 报 `CertificateHostMismatch` |
| SOCKS5 CONNECT，IPv4 目标 | 200 / 内容正确 |
| SOCKS5 UDP ASSOCIATE（UoT v2）：经 `1.1.1.1:53` 的 DNS、16 KiB 回显、同一关联内两个目标 | 响应正确，16 KiB 数据完整，超限数据报被丢弃且不破坏关联 |
| 域名目标（由服务端解析） | 200 / 内容正确 |
| 10 MB 传输 | SHA-256 与源文件一致 |
| 8 个并发请求 | 内容全部一致，复用同一会话（stream 2–8） |
| 单 stream 45 秒 keep-alive，空闲超时 2 秒 | 9/9 响应，活跃会话未被回收 |
| 客户端断开后的线程/stream 清理 | 18 → 2 个线程，RSS 1.0 MB → 空闲过期后 492 KB |
| 会话复用 / 空闲池 | 3 个请求 → 1 个会话；空闲超时后会话关闭 |
| 错误密码 | 快速失败（服务端关闭连接），客户端保持运行 |
| 服务端中途被杀后重启 | 首个请求干净失败，下一个请求自动重连 |
| 黑洞地址连接超时（`--connect-timeout 2`） | 2.0 秒内失败 |
| 半关闭（上传后客户端 `shutdown(WR)`） | 宽限期后有限时间内拆除；结果与参考 Go 客户端一致 |
| 同端口重复启动 | `AddressInUse`（不会因 SO_REUSEPORT 静默共享端口） |
| 日志凭据泄漏 | 所有日志中均无密码 |
| 交叉编译 `mipsel-linux-musleabi` / `mips-linux-musleabi` / `arm-linux-musleabihf` / `aarch64-linux-musl` / `x86_64-linux-musl` | ELF32 LSB/MSB MIPS32r2 o32 软浮点、ARM EABI5 硬浮点、ELF64 aarch64/x86-64，均为静态链接且无动态段 |
| OpenWrt apk（`scripts/make-apk.sh`） | ADB v3；用 apk-tools 3.0.8 安装到 chroot 验证，权限与依赖正确，覆盖 7 个构建变体 / 8 个包 |
| LuCI apk（`scripts/make-luci-apk.sh`） | ADB v3、`noarch`，可随 `luci-base` + `anytls-zig` 安装；`.lmo` 与官方 `po2lmo` 输出逐字节一致 |
| aarch64 吞吐 / 延迟 / CPU / RSS | [docs/bench-aarch64.md](docs/bench-aarch64.md)：106–376 MB/s、0.21–0.23 ms、1.3–1.7 MB RSS |

**未执行：** 在真实路由器硬件或 QEMU 上运行交叉编译的二进制。测试环境没有设备
和用户态 QEMU，因此目标架构上的运行时行为未经验证；只验证了 ELF/ABI 属性以及
本机架构上的代码路径。上线前请在设备上做一次冒烟测试
（`/etc/init.d/anytls-zig start`、`curl --socks5 …`）。

## 已知限制 / 有意的取舍

* 支持 SOCKS5 CONNECT 和 UDP ASSOCIATE（不支持 SOCKS4、HTTP CONNECT）。UDP 通过
  sing-box udp-over-tcp v2（`sp.v2.udp-over-tcp.arpa`）承载，因此服务端需要支持
  UoT（anytls-go 0.0.13 支持）。超过 16 KiB 的数据报会在本地丢弃：参考实现的
  UoT 读取缓冲区是 16 KiB。
* TOML 只支持一个小子集（不支持数组、内联表、多行字符串或点号键），并且对未知键
  直接报错而不是忽略。
* LuCI 只编辑 UCI；TOML 是面向命令行/系统服务部署的另一套机制，不由 Web UI 管理。
* 没有 `--disable-reuse`；会话始终多路复用并池化。
* 填充方案上限：16 个包、每包 16 项、方案文本 4 KB、填充帧最大 4 KB。更大的服务端
  方案仍可工作，但最大的填充尺寸会被截断（只影响流量形态，不影响组帧）。
* 一个会话在其生命周期内使用同一份 `paddingScheme` 快照；更新按协议文档只作用于
  新会话。
* 半关闭连接会等待 `--half-close-wait` 秒（默认 3）以等待对端 FIN。anytls-go 在
  收到 FIN 后直接关闭 stream 而不回 FIN，若无限等待会泄漏连接；该参数用于在有限
  滞留与“客户端 EOF 后目标应答较慢”的场景之间取舍。
* `cmdSYNACK` 失败只关闭对应 stream；SYNACK 超时则关闭整个会话（与参考实现一致）。
