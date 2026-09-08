# 支持与验收矩阵（研究阶段）

核对日期 2026-09-08。所有“支持”均为拟发布范围，真实 UEFI、双向重启与 GUI 验收尚未执行；Task 1 BLOCKED。不得将主机包版本记录当固件兼容认证。

| 环境 | 地位与架构 | 已知实际版本 / 缺口 | 验收范围 |
|---|---|---|---|
| Windows 11 | 主要实机，x86-64 / x86_64-pc-windows-msvc | 用户指定；具体版本、build、固件未知 | UAC 双账户情形、MSI 安装/卸载/ACL、应用阻止重启、中文/Unicode/高 DPI、实际进 Arch |
| 当前 Arch Linux KDE Plasma Wayland | 主要实机，x86-64 / x86_64-unknown-linux-gnu | 当前执行环境只读查询：kernel 7.2.3-zen1-3-zen；systemd 261.2-1；glibc 2.44+r24+g16be1518495f-1；polkit 127-3；plasma-desktop 6.7.4-1；plasma-workspace 6.7.4-3；kwin 6.7.4-7。Wayland 是用户指定，未自行读取活动会话验证 | 原生 Arch 包、图形认证代理、root inhibitor 行为、Unicode/缩放、实际进 Windows |
| Ubuntu 24.04 LTS | 稳定参考和 UEFI VM，x86-64，Wayland/X11 | 官方 noble 包基线 systemd 255、glibc 2.39；实际 VM 的 kernel、包修订、桌面、固件版本缺失 | .deb、systemd255 inhibitor、Wayland/X11、OVMF/UEFI VM 图形、双向切换；虚拟机不替代实机 |

Arch 记录来源：2026-09-08 本工作环境运行 `cat /etc/os-release`、`uname -r`、`systemctl --version`、`pacman -Q glibc systemd polkit plasma-desktop plasma-workspace kwin rust cargo`；最后命令因 rust/cargo 不归 pacman 管理退出 1，其余包结果如上。不等于 Rust 不存在。Ubuntu 依据：[systemd 包](https://packages.ubuntu.com/noble/systemd)、[libc6 包](https://packages.ubuntu.com/noble/libc6)。不扩大为所有 systemd 发行版，不包含 ARM、传统 BIOS、共享单条多 OS 引导项。

## 已发布依赖版本候选

| 依赖 | 本次核查固定版本 | 官方声明最低 Rust / 平台 | 决定与未验证项 |
|---|---|---|---|
| Rust | 1.98.1 stable（2026-09-03 发布） | 使用两个上述 target | 不安装；以发布版本固定工具链，后续 Cargo.lock 固定传递依赖 |
| slint / slint-build | 1.17.1 | slint manifest rust-version 1.92，edition 2024 | 仅 GUI 依赖；二者必须同版；尚未实际 resolve/compile |
| windows | 0.62.2 | rust-version 1.82，edition 2021 | 仅 Windows 平台/helper 条件依赖所需 Win32 features |
| zbus | 5.19.0 stable | 发布 tag workspace rust-version 1.87，edition 2024 | 仅 Linux 平台/helper；系统总线，不依赖 GUI 的 session bus |

来源：[Rust 发布目录](https://blog.rust-lang.org/)、[Slint 发布 Cargo.toml](https://docs.rs/crate/slint/1.17.1/source/Cargo.toml)、[windows 发布 Cargo.toml](https://docs.rs/crate/windows/0.62.2/source/Cargo.toml)、[zbus 发布列表](https://docs.rs/crate/zbus/5.19.0)、[zbus-5.19.0 正式 tag](https://raw.githubusercontent.com/z-galaxy/zbus/zbus-5.19.0/Cargo.toml)。这证明顶层声明的 Rust 版本兼容，**不等于**已经验证完整依赖图或编译成功。没有使用 main 分支作为依赖，也未创建 Cargo 工程。

GUI 候选固定 Slint Winit+FemtoVG，显式选择 backend-winit-wayland/backend-winit-x11 与 renderer-femtovg，关闭无关默认功能，核心和 helper 不引入 Slint。Windows 保持 GUI subsystem。Skia 仅在 GUI 验收失败且有证据时再评估，不默认使用 software renderer。上游 desktop/backends/latest 页面于访问日核对，但可随版本变化；实施时对应发布 tag/锁定包复核。[Slint 平台](https://docs.slint.dev/latest/docs/slint/guide/platforms/desktop/)、[后端](https://docs.slint.dev/latest/docs/slint/guide/backends-and-renderers/backends_and_renderers/)、[Winit 依赖](https://docs.slint.dev/latest/docs/slint/guide/backends-and-renderers/backend_winit/)。

## 构建、分发和系统依赖

Linux `.deb` 在 Ubuntu 24.04 glibc 2.39 基线构建，防止从 Arch glibc 2.44 带入更高符号需求。选择 GNU target，不承诺 musl GUI。产物后续用 `readelf --version-info` 检查所需 GLIBC 版本不高于 2.39，用包依赖工具与两种桌面验证；Rust target 的最低 glibc 不等于链接出的 GUI 二进制最低要求。Arch PKGBUILD 在原生干净 Arch 构建环境编译，不把 Arch ELF 直接装进 Ubuntu。

| 包 | 构建依赖候选 | 运行依赖与安装边界 |
|---|---|---|
| Arch 原生 `.pkg.tar.zst` / PKGBUILD | base-devel、固定 Rust 工具链、pkgconf；按实际 native crates 补充依赖 | glibc、systemd>=255、polkit>=124、KDE 已工作的认证代理；Wayland/libxkbcommon、图形驱动/EGL/OpenGL；如启用 X11 则 libx11/libxi/libxcursor/libxkbcommon-x11。由 ELF 与 GUI 实验核对精确列表 |
| Ubuntu 24.04 `.deb` | build-essential、pkg-config、固定 Rust、dpkg-dev/debhelper；原生依赖开发包按锁定构建核对 | libc6>=2.39、systemd>=255、pkexec/polkitd（Ubuntu 分包）、认证代理；libwayland-client0/libxkbcommon0/libegl1/libgl1；X11 的 libx11-6/libx11-xcb1/libxi6/libxcursor1/libxkbcommon-x11-0。最终用 dpkg-shlibdeps + dlopen 依赖检查 |
| Windows MSI | 固定 Rust MSVC target、Visual Studio C++ Build Tools/Windows SDK、WiX 7.0.0 与兼容 .NET SDK（官方 CLI 最低 .NET6）；不安装于本任务 | Windows11 x86-64，Program Files helper / ProgramData 可信记录 ACL；若使用动态 MSVC runtime 则声明/打包 Microsoft VC++ x64 runtime，静态/动态策略待构建验证 |

表中的图形依赖是待构建验证候选，不能据此提前声称安装包可用。Slint Winit 文档列出 X11 运行库；Wayland/渲染器依赖还须锁定 feature 后验证动态加载项。基础打包依据：[Debian control 依赖字段](https://www.debian.org/doc/manuals/maint-guide/dreq.en.html)、[WiX 官方构建方式](https://docs.firegiant.com/wix/using-wix/)。Arch wiki 本次返回 anti-bot 页面，未据其正文作已核实结论；PKGBUILD 依赖列表最终需按原生构建检查。

WiX7 官方文档要求显式 EULA 接受并有维护费条款，发布者需按实际使用条件处理；本研究未接受任何条款或产生费用。Slint 1.17.1 manifest 提供 GPL-3.0-only / Slint Royalty-free 2.0 / Slint Software 3.0 选择；发布前按选择复核并完成 attribution，不能把研究视为许可证选择。[WiX 条款说明](https://docs.firegiant.com/wix/osmf/)、[Slint 条款](https://slint.dev/terms-and-conditions)。

## 验收矩阵与门槛

| 层级 | 必须覆盖 | 本次状态 |
|---|---|---|
| 研究/夹具 | 真实 Windows/Linux 启动项；同目标正常更新配对；每个身份变换正反证据；格式字段逐项归属 | BLOCKED：全部真实夹具缺失 |
| 纯测试 | parser 边界、未知 OptionalData、未知记录版本、helper 篡改参数、阶段 Unknown、超限/超时/断连、ABA 恢复拒绝 | 未开始，禁止访问宿主固件 |
| 包与 GUI | 两端目录保护；普通用户不能改记录/helper；中文/其他 Unicode、缩放、高 DPI；Arch Wayland、Ubuntu Wayland/X11、Windows | 未开始 |
| inhibitor/应用阻止 | systemd255 root+block/delay、261 root+block/weak/delay，Windows 未保存应用和 UAC 不同账户 | 未执行，需独立显式授权 |
| UEFI VM 和实机 | 双向 switch；BootNext 冲突/存在/丢失；比较每次 BootOrder 前后；分别记录 API、读回、重启接受、人工 OS 观察 | 未执行，需独立显式授权；BootOrder 变化即失败 |

发布前补齐 Windows 精确 build/固件、Ubuntu VM 版本、Arch 活动会话/固件元数据，记录统一 release 构建的包大小、安装占用和额外依赖。当前没有体积数据，不设未经测量的承诺。
