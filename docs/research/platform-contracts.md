# 平台契约（官方研究，待实机验收）

首次访问日期2026-09-08；证据/产品约束更新2026-09-09。Task 1 状态 BLOCKED，原因见 [identity](identity.md)。本文固定实现候选的API、输入边界和失败语义。此后controller经用户授权，已在Arch普通权限下完成一次私有只读采集；这只验证当前变量可读取和本地解析，不等于生产平台实现或固件启动行为验收。未运行提权、Windows固件API、UEFI写入或重启测试；生产实现仍须等研究门槛放行。

2026-09-10调度：Linux-first独立审查Approved，用户条件授权生效，按1S/1L/1W放行，替代旧Windows证据全局阻塞。[共享/Linux前置契约](shared-linux-prerequisites.md) 已收敛有界解析、完整保守identity、固定对象/锁/错误/资源与fake清单；1S.parse/1S/1L均READY_FOR_REVIEW，不自行标通过。1W仍BLOCKED，仅阻Windows分支及最终跨平台声明；不提前触发真实写入/重启，真实验收另行授权。

## UEFI 访问与发现范围

全局变量 GUID 为 `8be4df61-93ca-11d2-aa0d-00e098032b8c`。BootNext/BootCurrent 的值恰为小端 u16，BootOrder 为长度为偶数的 u16 数组。Windows 得到的 payload 不含 efivarfs 属性前缀；Linux 文件前四字节单独解析。读取设置和请求启动是不同证据阶段。[UEFI 2.10 §3](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html)、[efivarfs 文档](https://docs.kernel.org/filesystems/efivarfs.html)。

Windows 固件 API 固定 `GetFirmwareEnvironmentVariableExW` / `SetFirmwareEnvironmentVariableExW`，API 最低 Windows 8 desktop，产品最低 Windows 11 x86-64。使用进程 token 的 `OpenProcessToken`、`LookupPrivilegeValueW`、`AdjustTokenPrivileges` 启用 `SeSystemEnvironmentPrivilege`；BOOL 成功仍须检查 `ERROR_NOT_ALL_ASSIGNED`，不足则停止。所有句柄/缓冲区长度检查，缓冲扩容有上限，错误立即捕获 `GetLastError`。启动环境可用 `GetFirmwareType` 辅助检查；失败不能解读为 BIOS。[读取 API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw)、[写入 API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexw)、[AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)。

Windows inspect 的发现范围明确为 **BootOrder 引用编号并集 BootCurrent/BootNext 引用编号**，去重后读取每个 Boot####。额外读 switch/configure 已知编号只能定位既有目标，不构成扩大枚举。任何关联项读取失败都报告诊断；BootOrder 格式无效不能以空列表继续。GetFirmwareEnvironmentVariableExW 是按名称读取 API，本轮未确立有公开文档的通用用户态枚举 API，因此不使用 NtEnumerateSystemEnvironmentValuesEx、未文档化 API 或 65536 次扫描。不在引用集合里的孤立项不会出现在 Windows 候选列表；不能声称列举全部条目。Linux 仅枚举 efivarfs 全局 GUID 下严格匹配 `Boot[0-9A-F]{4}` 的文件，可列出孤立项并标明引用状态，不写 BootOrder。

Linux 最低支持环境为已挂载且可访问 efivarfs、systemd 255、polkit 124 的矩阵环境；内核单独版本不是足够能力证明。路径固定 `/sys/firmware/efi/efivars`，检查文件系统类型与目录对象，拒绝 symlink/意外文件类型，读取限制、短读与变化错误明确报告。不自动 mount、不清除 immutable 标志、不创建/修复启动项。允许的将来写操作仅对 BootNext；写缓冲为小端属性 7 与两字节目标。BootNext 不存在仅能由明确 NotFound 判定。其他变量仅只读。

产品限制（非规范给定值）：单变量 payload 上限 1 MiB；超过上限返回 ResourceLimit，不截断解析。BootOrder 最多由 u16 空间表达的 65536 个编号，重复编号去重但保留诊断；实际输出受 IPC 总上限约束，不能把截断结果显示成完整发现。

收敛补充：单次枚举保留raw累计<=1 MiB（Linux前缀计入）；单份受保护记录<=1 MiB；IPC仍各帧/累计64 KiB。计数域独立，超限ResourceLimit且无部分完整结果。固定操作锁及rename后fsync持久化未知边界详见共享契约§3，不把原子替换承诺为失败回滚。

## 正常重启

Windows 选定 `InitiateSystemShutdownExW(NULL, NULL, 0, FALSE, TRUE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED)`，即本机、无自设倒计时提示、禁止强制关闭应用、重启、planned reason `0x80000000`。API 最低 Windows XP desktop；产品只验收 Windows 11。helper 启用 `SeShutdownPrivilege` 并核对实际授予。BOOL 非零映射 Accepted，零值连同错误映射 Rejected；调用期间 helper 退出或结果丢失映射 Unknown。系统仍可因应用/服务/用户而取消或延迟。该选择支持提权采用不同管理员凭据的场景。[InitiateSystemShutdownExW 参数与异步返回](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-initiatesystemshutdownexw)。

已评估 `ExitWindowsEx(EWX_REBOOT, reason)`：必须启用 shutdown 权限，禁止 EWX_FORCE/EWX_FORCEIFHUNG；但调用者不在交互用户 logon session 时可成功而不关机。为避免把 UAC 不同账户登录上下文当已验证相同会话，MVP 不采用它；也不退回 shell `shutdown` 命令。[ExitWindowsEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex)。

Linux 选定系统总线 `org.freedesktop.login1`、对象 `/org/freedesktop/login1`、接口 `org.freedesktop.login1.Manager` 的 `RebootWithFlags(t)`，参数严格 `uint64 1`（`SD_LOGIND_ROOT_CHECK_INHIBITORS`）。最低**支持基线** systemd 255；这是核查和矩阵下限，不声称方法首次加入于 255。不使用 kexec、soft reboot、skip-inhibitors 标志。方法存在的 introspection、版本与支持策略检查在写 BootNext **之前**完成；未知方法/未知参数/不受支持版本一律停止，不退回普通 Reboot 或 reboot syscall。[systemd v255 正式 tag 的 logind 文档](https://raw.githubusercontent.com/systemd/systemd/v255/man/org.freedesktop.login1.xml)。

v255 文档明确 privileged caller 在 flags=0 时可能忽略 inhibitors，flags=1 要求检查。v257 起普通 block 锁默认约束 privileged caller，flag 1 继续覆盖 weak 锁；v261 文档保留此约定。检查 v257 文档发现 SKIP_INHIBITORS 的正文十六进制示例与位定义不一致，BootHop 不使用该标志；只取三版本一致的 ROOT_CHECK=1。[v257 文档](https://raw.githubusercontent.com/systemd/systemd/v257/man/org.freedesktop.login1.xml)、[v261 文档](https://raw.githubusercontent.com/systemd/systemd/v261/man/org.freedesktop.login1.xml)。

block/block-weak 的拒绝和 delay 锁等待必须分别验收；delay 受 logind 的 `InhibitDelayMaxUSec` 上限约束，不承诺无限等待或所有桌面应用均注册锁。`ListInhibitors`/`CanReboot` 只能作诊断，读取与请求之间有竞态，不能替代实际方法的检查。收到方法成功回复才是 Accepted；明确 error reply 是 Rejected；D-Bus 断连/超时/系统离线且未取得明确回复是 Unknown。`PrepareForShutdown` 信号不是本次请求的唯一关联成功证据。[systemd inhibitor 说明](https://systemd.io/INHIBITOR_LOCKS/)。

发布 gate：Ubuntu 255 与实际 Arch 261 均须以 root helper 请求验证 block 不被绕过、delay 正常等待、261 weak 锁被检查；同时测试 Windows 标准用户 UAC/同用户提升/不同管理员凭据、应用阻止、多会话。当前这些测试全部未运行。如实际行为不符合要求，阻止发布并返回设计审阅；官方文档核对不替代运行结果。

## IPC 与授权

产品常量：协议 envelope 版本1；长度前缀u32 LE + UTF-8 JSON。依已批准Task9统一约束，请求和响应各以 **64 KiB** 为上限，长度前缀计入该上限；单次操作接收的所有响应帧与stderr诊断合计也不得超过64 KiB。超限明确报告 `ResourceLimit`，不截断后继续解析或将部分枚举显示成完整结果。它是产品资源约束，非官方API要求；初稿中的1MiB响应/8MiB累积没有需求证据，本版不采用。若后续需扩大，须由controller明确裁定和统一契约，不能由平台或GUI各自增加。

一个操作一条请求，阶段报告必须带同一个request_id；未知版本、未知字段、重复字段、超长帧、额外请求拒绝。授权/连接等待120秒，建立后请求/读写等待30秒；重启RPC回复等待30秒。这些等待时间同属产品选择，须fake测试边界，不是OS默认值。GUI不阻塞主线程等待；私有研究采集器的文件大小限制不是产品IPC限制，也不将raw固件内容作为常规GUI响应。

Linux 固定 exec `/usr/bin/pkexec --disable-internal-agent /usr/lib/boothop/boothop-helper`，通过 argv 数组调用，不调用 shell，不采用 GUI 指定路径。helper 路径、policy action、父目录均 root 可写；`org.freedesktop.policykit.exec.path` 精确对应安装路径，禁止 keep 授权规则导致任意参数受信。仅传受限 stdin/stdout/stderr 管道，关闭其他继承 FD；环境不传 loader 注入变量；helper 检查 euid=0、管道类型、版本/长度/操作，不信任 PKEXEC_UID 或 GUI 发来的 identity。GUI 不被提升、不保留 DISPLAY/XAUTHORITY 特例。pkexec exit 126 表示取消，127 表示未授权或其他错误，不能把 127 单独诊断成没有认证代理。禁用内部代理后依实际失败提供“取消 / 授权失败 / 无法确定的授权环境错误”，不声称可靠预检测认证代理存在。[pkexec 官方手册](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)。

Windows 固定安装路径由 `FOLDERID_ProgramFiles` 加 `BootHop\boothop-helper.exe` 组成，安装目录管理员保护；GUI 使用 `ShellExecuteExW`，verb=`runas`，`SEE_MASK_NOCLOSEPROCESS`，保留返回进程句柄直至协议结束。helper 不能由请求参数指定，命令行仅受限 pipe 名后缀、request_id、GUI PID，不拼接用户文字。`ERROR_CANCELLED` 是 UAC 取消，其他创建失败不假定同义。[ShellExecuteExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)。

GUI 在本机创建随机 128-bit nonce 后缀的 `\\.\pipe\BootHop-<hex>` 单次 server，`FILE_FLAG_FIRST_PIPE_INSTANCE`、`PIPE_REJECT_REMOTE_CLIENTS`，最大实例 1。显式 DACL 仅调用 GUI 的用户 SID、SYSTEM、提升 Administrators，授予协议需要的访问位；不依赖默认 DACL，不授 Everyone/Anonymous，不授不必要 create-instance 权限，阻止低完整性写入。提升 helper 为 client，服务端 `GetNamedPipeClientProcessId` 必须等于 ShellExecute 返回的仍存活进程 PID；读 token 的 `TokenElevation`、`TokenIntegrityLevel` 检查已提升，读映像路径核对固定 helper。不能查询、PID 不符、路径/权限不符均拒绝。helper 用 `GetNamedPipeServerProcessId` 查询 GUI，持有其进程句柄并核查会话、映像固定 GUI 路径及进程仍存在；单凭 nonce/PID 不当认证。不同管理员凭据用管理员 ACE 容纳，不错误要求提升 token 用户 SID 等于 GUI SID。[管道 ACL](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)、[client PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)、[server PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)、[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)。这些 API 均早于 Windows 11；具体权限组合必须在 Windows helper 集成测试中验证，查询失败绝不降低验证。

任何平台超时/断连/输出超限：若能证明未发送操作，只报告 IPC/授权失败且 NotAttempted；操作发送后未收到终态，则相关固件/重启阶段 Unknown，保留已确认阶段，可能残留 BootNext。不得重试 switch 或发送删除来“修复”超时。写入前发现 GUI 断连可以停止；写入之后 helper 仍须完成可安全执行的读回与报告，未知结果不得以杀进程假造 Rejected。

## 存储、竞态和阶段报告

Linux 固定 `/var/lib/boothop/targets.json`，root:root 目录 0700、文件 0600；helper `/usr/lib/boothop/boothop-helper`。Windows 固定 `FOLDERID_ProgramData\BootHop\targets.json`，目录/文件 ACL 只允许 SYSTEM 和提升管理员写；helper 安装于受保护 Program Files。路径不接收 GUI/环境变量覆盖。两端各自维护对侧 OS 目标，per-OS 首次配置互不共享。

记录envelope未知版本必须UnsupportedRecordVersion；按已批准opaque修订，未知身份组件种类/版本/算法同样是不支持记录，普通configure不覆写，损坏摘要也拒绝。只有明确NotFound才是未配置。记录不含原始OptionalData，指纹不默认公开；configure从同一读取buffer生成结构字段和完整opaque组件，失配不自动重登记。原子同目录替换配合落盘/权限保护，读取错误不吞掉。helper整次inspect/configure/switch持本产品互斥锁；这无法阻止其他固件工具、固件自动维护或另一OS写入。

Windows SetFirmwareEnvironmentVariableExW 与 Linux efivarfs 均无已核实 compare-and-swap/事务语义。写前读、写后读不构成外部原子保护，值相同也无法排除 ABA。默认恢复策略：无法证明独占与无外部变化则不恢复，报告可能残留。原本已有同一 BootNext 的状态不归本次操作所有。Accepted/Unknown 重启不回滚。报告独立携带目标验证、BootNext 设置/读回、重启请求；读取不能证明固件将遵守 BootNext 或目标 OS 实际启动成功。

## 本轮契约核对与剩余证据

| 项目 | 无额外实机操作可确认的依据 | 仍未完成的验证 |
|---|---|---|
| UEFI/efivarfs读取与属性分离 | 官方格式已核对；私有Arch采集8个raw文件哈希/两次内容一致，2个真实项有用户OS标签 | 1L生产reader错误/fake清单核对；Windows原生API out attributes/payload另归1W |
| Windows发现 | 固定BootOrder并集BootCurrent/BootNext引用范围与孤立项限制，公开读取API契约已明确 | Windows实际发现和权限；不承诺完整枚举 |
| 正常重启 | Win32非强制参数/异步返回及logind255/261 flag1依据已核对 | 应用阻止、root block/block-weak/delay、UAC不同账户和多会话实验 |
| IPC/存储 | 固定helper、权限保护、对端核验API、Unknown语义；按已批准64KiB对齐 | Windows具体token访问权、管道ACL及两平台端到端集成 |
| identity消费 | 私有样本支持外层观察；内部仍opaque，已批准全部OptionalData（含空）完整长度+SHA-256严格组件 | 1S完整结构字段/正反依据仍阻identity；1W只阻Windows分支，不混作共享gate；内部解码与配对只约束未来放宽，公开原文不要求 |

本轮没有执行表中待完成操作，也未把Windows主机/更新事件缺口改成已验证。下一步按Linux-first审查和各子门槛决定；contract/fake不算Windows实证，Linux开发包不算最终跨平台发布。Task1整体未完成不能替代各分支具体状态。
