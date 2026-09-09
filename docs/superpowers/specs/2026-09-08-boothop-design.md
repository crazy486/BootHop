# BootHop MVP 设计

日期：2026-09-08。状态：整体设计已获用户批准，已按要求补充未知版本 fail closed 和 per-OS 首次配置规则；允许进入 writing-plans，不开始生产代码。本文不授权真实固件修改或重启验收。

## 1. 产品与支持范围

BootHop 是按需打开的单窗口桌面工具：Linux 上点击“重启进入 Windows”，Windows 上点击“重启进入 Linux”。首次配置后，点击即确认，不另弹重复重启确认框；主界面明确显示“点击后将立即重启，请先保存工作”。系统 UAC / polkit 授权保留。

MVP 支持 Windows 11，以及使用 systemd、具有可正常工作 polkit authentication agent 的 Linux 桌面。机器必须通过 UEFI 启动，Windows 与 Linux 必须有独立、可识别的 UEFI 启动项，固件必须正确实现 BootNext。Linux 启动项不限定 GRUB、systemd-boot 或其他具体引导器。

首轮主要实机组合为 Windows 11 x86-64 + 用户当前的 Arch Linux / KDE Plasma / Wayland。Ubuntu 24.04 LTS 保留为稳定参考与 UEFI 虚拟机验收环境；这不构成对所有发行版的支持承诺。

不包含托盘、自启动、后台常驻、引导项创建或修复、BootOrder 修改、传统 BIOS 支持。发现配置异常时诊断并停止。BootHop 不自行实现或捆绑认证代理。

BootHop 能验证启动项配置并请求一次性启动，不能证明引导器最终启动哪个 OS、完整启动链正常，或固件一定遵守请求。BootNext 读回成功不构成固件启动行为已验证。

## 2. 架构与技术选型

- Rust 共享核心：二进制解析、身份识别、验证规则、流程状态与错误语义。
- Windows/Linux 平台层：UEFI 访问、受保护存储、权限及正常重启集成。平台抽象保持轻量，不强行统一底层机制。
- privileged helper：按需提权运行，作为最终安全边界，操作结束退出。
- 普通权限 Slint GUI：展示状态、收集意图、呈现结果与错误。

只有 GUI 包依赖 Slint；核心、平台代码和 helper 均不依赖 GUI 框架。GUI 使用 Winit backend，首选 FemtoVG，最终选择由 GUI 验收决定；实际失败后再评估 Skia。不采用当前存在文字体系限制的 Slint Software Renderer 作为默认方案。

不预设未经测量的体积目标。实现后以统一 Release 配置记录安装包、安装后占用和额外系统依赖。若使用 Slint Royalty-Free License，发布前按实际版本复核条款，优先在公开下载/发布页满足 attribution。

## 3. 三个 helper 操作

三者共用枚举、解析、身份生成与验证代码，不能出现配置和切换两套判断规则。

### inspect

发现、只读验证和诊断当前 UEFI 状态。用于首次配置、重新选择和失效后的重新发现。不写固件或更新可信目标配置，不重启。需要权限时允许触发 UAC / polkit。

### configure

接收候选编号及用户表达的 Windows/Linux 归类，重新读取真实启动项，独立解析、验证并生成 canonical identity，原子更新受保护记录。GUI 提供的 identity 不可信。自动归类和人工选择最终使用同一个 configure 流程。不修改 UEFI 或请求重启。

### switch

只接收切换到已登记 Windows/Linux 目标的意图。目标编号和 identity 来自受保护记录，不能由 GUI 参数替换。重新读取当前状态并独立验证后，才可修改 BootNext、读回确认和请求正常重启。

## 4. 存储与信任边界

GUI 缓存只供显示，不是实时验证结果，也不是 helper 的可信依据。普通启动 GUI 不主动提权；显示已保存目标及缓存状态。执行时再提权，以真实 UEFI 和受保护记录为准。

可信目标记录及其所在目录、helper 安装位置依赖管理员/root 写权限保护。记录包含格式版本、目标 OS 归类、定位编号和 canonical identity。更新使用原子替换，失败保留原记录。

未知或较新的记录格式版本必须 fail closed。UnsupportedRecordVersion 与尚未配置是不同状态；inspect/configure/switch 中依赖该记录的操作必须停止。当前版本不能通过普通 configure 覆写不支持的记录，也不能把读取失败解释为记录不存在。提示“当前 BootHop 版本无法读取该配置，请使用兼容版本或升级；如需恢复，应使用未来明确的管理员恢复流程”。MVP 不新增 reset 功能。独立于记录的只读环境诊断仍可返回，但不能将未知版本显示成可首次配置状态。

首次配置是 per-OS 的：Linux 首次使用时在 Linux 本地登记 Windows 启动目标；Windows 首次使用时在 Windows 本地登记 Linux 启动目标。一侧完成配置不会自动配置另一侧。两端分别维护各自受保护记录，MVP 没有跨系统共享配置。

helper 将所有 GUI 参数视为不可信输入。未经登记或身份不匹配的目标不能通过 switch 写入 BootNext。configure 本身必须经过操作系统授权；用户主动批准恶意提权操作不属于本 MVP 威胁模型。不引入 TPM、加密或自定义密钥。

## 5. 目标发现与 canonical identity

Boot#### 编号仅用于定位。原编号不存在、稳定身份不符或无法验证时停止，要求重新配置，不追随相似编号。

canonical identity 基于结构化稳定字段，设备路径是核心证据。不能把整个 EFI_LOAD_OPTION、所有 Attributes 或 OptionalData 无差别逐字节比较。显示名称不单独承担身份判定。影响可执行性但不属于身份的字段仍须独立验证。

自动归类需要正向证据且目标唯一，不能因“不是 Windows”或只有一个候选就推断 Linux。有歧义、名称模糊或证据不足时请求用户选择。人工确认补充 OS 语义，不绕过结构和身份检查。

字段级规则必须在实现身份判定前完成专项核对：依据 UEFI 格式文档和真实只读样本，明确设备路径规范化、相关属性及已知 OptionalData 格式的处理方式，并配套测试夹具。未知且可能影响目标的数据不得静默忽略；不支持的格式明确拒绝。尚未批准任何具体字节级比较算法或自动识别白名单。

## 6. 切换流程与并发

1. 读取受保护记录与当前 UEFI 状态，验证环境、目标结构及 identity。
2. 读取 BootNext。若指向其他目标，停止；若已是本次目标，保留该状态，不重复创建或在失败时清除。
3. 原本不存在 BootNext 时，写入本次目标；记录修改前状态与本次是否执行写入。
4. 重新读取并确认 BootNext 正确，才允许请求重启。任何前置步骤失败不得请求重启。
5. 发起正常重启，不使用强制关闭应用的方式。
6. 分别报告设置验证结果和重启请求结果。

BootHop 自身并发操作应串行化，但内部互斥不能阻止其他固件工具修改状态。平台接口核对必须说明检查和写入间的竞态；不得宣称能对外部写入提供尚未证实的原子保护。

## 7. 失败与恢复

恢复指严格恢复修改前状态，不等于清除 BootNext。修改前已是本次目标的状态不归本次操作所有，不清除。

写入后读回失败，或系统明确拒绝/无法发起重启时，才评估恢复。恢复前重新读取，只有能够确认不会覆盖外部后续修改时才执行。读不到、值发生变化或不能确认安全时，不再写入，明确报告状态未知或可能残留。

读回值等于本次目标并不能证明没有外部写入。若平台没有足够的并发保证，保守保留状态并报告；“尽力恢复”不构成必须执行一次删除的要求。

重启请求已接受后不回滚。机器未立即重启可能是正常关机流程延迟或被应用阻止。请求结果未知时不能假定被拒绝，不据此回滚。

界面和日志区分目标验证通过、BootNext 设置并读回成功、重启请求已接受。只有验收中的人工观察可记录实际进入目标系统；应用不能据前述阶段宣称启动完成。

## 8. 平台集成依据

Windows 优先使用 GetFirmwareEnvironmentVariableExW / SetFirmwareEnvironmentVariableExW 等官方固件变量接口；读取也需要相应权限，因此首次 inspect 可要求 UAC。枚举入口、权限启用、正常重启 API 和 IPC 的具体选择应在平台实现计划中明确。

Linux 优先通过 efivarfs 访问变量，解析其四字节变量属性前缀。systemd/logind 只负责正常重启集成，polkit/pkexec 负责提权。使用 pkexec --disable-internal-agent 禁止退回内部文本代理。不能仅凭通用失败码把所有授权失败都诊断为缺少代理；明确区分已知取消、授权失败及无法进一步确定的环境问题。

helper 不能通过 root 身份或所选 API 隐式绕过用户要求的正常关机语义；logind inhibitors、Windows 应用阻止关机及异步返回语义须纳入平台验收。

## 9. 测试与验收

普通测试命令只能使用 mock/fake 平台接口，不能访问宿主 UEFI 或触发重启。真实固件和重启验收独立、显式执行，不能被普通测试命令意外触发。

测试层级：

1. 解析与 identity 单元测试：正常、截断、畸形与 Unicode 数据；非身份变化容忍、稳定身份变化拒绝。
2. 核心执行流程测试：目标失效、冲突、写入/读回失败、重启拒绝/接受/结果未知及恢复分支。
3. helper 权限边界测试：篡改 GUI 编号、缓存与 identity；switch 不能绕过受保护记录；configure 独立生成 identity。
4. UEFI 虚拟机及实机验收：双向真实切换与失败反馈。

幂等性覆盖：已有目标 BootNext、多次 inspect、重复验证，无额外副作用。恢复覆盖：原值不存在、已是目标、外部修改、读取失败；已接受重启请求不得回滚。

每次真实切换比较前后 BootOrder；永久顺序变化即失败，即使成功进入目标 OS。分别记录接口调用成功、BootNext 读回成功、系统接受重启请求和人工确认目标 OS。

GUI 验收覆盖 Windows 11、Linux Wayland/X11、中文及其他 Unicode、启动项 Unicode description、高 DPI/缩放、UEFI 测试虚拟机图形环境。FemtoVG 未通过时根据证据评估 Skia。

## 10. 进入实现前的收敛事项

本文确定产品与架构，并不把尚未验证的细节视为已成立。实现计划先安排只读研究与样本核对，产出 canonical identity 字段表、正向归类规则、平台枚举/重启/IPC 方案和明确的系统版本、CPU 架构及发行包矩阵。规则不能满足本文边界时，回到设计审阅，不悄悄降低安全要求。

在用户整体审阅本文后进入 writing-plans；本文阶段不生成生产代码，不执行真实固件测试。

## 官方参考

### Task 1 技术附录（2026-09-08，研究门槛未通过）

Windows MVP 发现范围收敛为 BootOrder 引用编号，补充 BootCurrent/BootNext 引用编号；不包含未引用的孤立 Boot####，不声称穷尽固件所有条目。不使用未文档化枚举 API 或扫描 65536 个编号。Linux 可读取 efivarfs 中严格匹配的全局 Boot#### 并标明引用状态。详见 `docs/research/platform-contracts.md`。

官方研究提出 Windows 使用非强制 `InitiateSystemShutdownExW`、Linux systemd>=255 使用 `RebootWithFlags(uint64 1)` 的契约；具体会话/inhibitor 行为仍待独立授权验收。2026-09-09更新：经授权在Arch取得2个私有真实启动项，用户分别确认对应Arch Linux和Windows11；两次连续读取一致不构成正常更新配对。Windows非空OptionalData尚为opaque，身份算法和自动归类白名单未冻结，正常更新前后证据与Windows原生API验证仍缺失。Task1为BLOCKED，不能据文档或只读采集成功放行后续实现。详见 `docs/research/identity.md`、`docs/research/windows-optionaldata.md`、`docs/research/support-matrix.md` 与仅记录非敏感证据计数的 `fixtures/uefi/manifest.json`。

- UEFI Boot Manager：https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html
- Windows 读取：https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw
- Windows 写入：https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexw
- Windows 重启语义：https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex
- efivarfs：https://docs.kernel.org/filesystems/efivarfs.html
- pkexec：https://polkit.pages.freedesktop.org/polkit/pkexec.1.html
- logind：https://github.com/systemd/systemd/blob/main/man/org.freedesktop.login1.xml
- Slint 平台：https://docs.slint.dev/latest/docs/slint/guide/platforms/desktop/
- Slint 后端：https://docs.slint.dev/latest/docs/slint/guide/backends-and-renderers/backends_and_renderers/
- Slint 许可：https://slint.dev/terms-and-conditions
- Tauri 比较依据：https://v2.tauri.app/start/prerequisites/
- iced 比较依据：https://github.com/iced-rs/iced
