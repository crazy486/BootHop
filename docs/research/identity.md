# UEFI identity 研究契约（Task 1，BLOCKED）

访问与核对日期：2026-09-08。这是官方资料阶段产物，不是已通过真实样本验收的身份算法。真实样本数、正常更新配对数均为 0；`fixtures/uefi/manifest.json` 是门槛状态的机器可读记录。所有拟议规则仍须真实正反样本核对，Task 1 未完成，依赖任务不得据此开始生产实现。

## 来源和解释边界

- [UEFI 2.10 §3.1.2–3.1.3、§3.3](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html)：load option、启动变量、OptionalData 和短设备路径语义。
- [UEFI 2.10 §10.3、§10.3.5.1、§10.3.5.4](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html)：节点边界、GPT/MBR 签名、路径拼接。
- [Linux efivarfs](https://docs.kernel.org/filesystems/efivarfs.html)：磁盘文件前四字节是小端**变量属性**；之后才是变量值。该在线页面未标明固定内核发布版本，不能用其渲染日期冒充版本。
- [Microsoft BCDBoot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11)：Windows EFI 安装目录、NVRAM 条目和 BCD 的关系。没有据此得到 OptionalData 的完整二进制稳定性契约。

以下拒绝策略是 BootHop 的保守支持范围选择，不代表 UEFI 禁止其他合法格式。`UnsupportedFormat` 是结构或安全语义不受支持；`NeedsConfirmation` 是结构受支持但 OS 证据不充分；二者不得混淆。

## 字段表

“拟身份”表示待样本确认的 canonical 字段，不是当前可用白名单。表中测试名均为待实施验收名，没有声称已存在或已运行测试。

| 字段 | 格式来源 | 是否身份 | 规范化方法 | 是否独立验证 | 样本 | 回归测试名 |
|---|---|---|---|---|---|---|
| Boot#### 编号 | UEFI §3.1.1，四位大写十六进制 UINT16 | 否，仅定位 | 解析为 u16；不追随其他编号 | 原编号存在、当前值可读 | 缺失 | `missing_original_id_stops` |
| 节点 type/subtype/length、顺序、结束节点 | UEFI §10.3 | 拟身份：有序结构 | 按节点解析；不把未知节点原样哈希后称为支持 | 长度至少 4、无溢出、恰好消费边界；单实例且一个完整路径 | 缺失 | `truncated_node_rejected`、`extra_path_rejected` |
| 硬件/ACPI/消息节点前缀 | UEFI §10.3 | 未决 | 不删除、不重排、不把完整路径折叠成短路径；初始候选范围暂不支持此前缀 | 未批准节点组合返回 UnsupportedFormat | 缺失 | `unknown_prefix_rejected` |
| HD 节点分区格式/签名类型 | UEFI §10.3.5.1 | 拟身份 | 初始研究候选仅 GPT=2、GUID=2；MBR、无签名均暂拒绝 | HD 节点长 42，分区号非零、签名非零 | 缺失 | `mbr_or_unsigned_rejected` |
| GPT UniquePartitionGuid、分区号 | UEFI §3.1.2、§10.3.5.1 | 拟身份 | GUID 字段按 UEFI 字节布局解析成固定语义值，分区号 u32；不改 GUID 大小端含义 | 拒绝不一致/重复目标；GUID 不是磁盘 GUID | 缺失 | `partition_guid_change_rejected`、`partition_number_change_rejected` |
| 分区起始 LBA、大小 | UEFI §10.3.5.1 | 未决：拟保守保留为独立字段 | 不擅自忽略移动/扩容变化；待真实更新证据决定是否身份或独立重验 | 非零大小、范围无溢出；无磁盘核对能力不得宣称已验证 GPT 内容 | 缺失 | `partition_geometry_change_requires_review` |
| FilePath 节点 UTF-16 路径 | UEFI §10.3.5.4 | 拟身份 | 拟支持单个绝对路径节点；保留 UTF-16 码元，不做 Unicode NFC、大小写折叠、斜杠替换、`.`/`..` 消解 | 终止符在节点内、无嵌入 NUL、有效编码；相对路径/歧义形式暂拒绝 | 缺失 | `loader_path_change_rejected`、`invalid_utf16_path_rejected` |
| 多 FilePath 节点拼接 | UEFI §10.3.5.4 给出分隔符合并/插入规则 | 未决 | 规范允许，BootHop 尚无正反样本；当前候选范围不允许此变换 | 暂 UnsupportedFormat，不能任意拼接字符串 | 缺失 | `split_path_not_silently_normalized` |
| Description | UEFI §3.1.3 | 否 | 仅显示；合法改名拟不改变身份；不 trim 后用名称分类 | 检查 UTF-16 NUL 结束、边界、有效编码，显示层转义控制字符 | 缺失 | `valid_description_change_preserves_identity`、`malformed_description_rejected` |
| EFI_LOAD_OPTION.Attributes | UEFI §3.1.3，值内 u32 | 否，独立可执行性策略 | 不整体参与 identity；拟允许 ACTIVE=1、HIDDEN=0/1、CATEGORY_BOOT=0 | 每次必须 ACTIVE；APP、保留位、FORCE_RECONNECT 暂拒绝，hidden 只影响展示 | 缺失 | `inactive_target_rejected`、`hidden_change_preserves_identity`、`reserved_load_attribute_rejected` |
| UEFI 变量 attributes | UEFI §3.3；Linux 前缀或 Win32 out 参数 | 否，独立存储策略 | 与上行严格不同；Boot####/BootOrder/BootNext 拟要求 NV\|BS\|RT=7；BootCurrent 为 BS\|RT=6 | 每次核对；未知认证/附加属性不静默接受 | 缺失 | `variable_attributes_not_load_attributes`、`unexpected_variable_attributes_rejected` |
| FilePathListLength | UEFI §3.1.3，u16 | 否，结构长度 | 与解析消费字节数相等，非身份哈希 | 校验 description、path、OptionalData 边界 | 缺失 | `path_list_length_overflow_rejected` |
| OptionalData 空值 | UEFI §3.1.3 | 拟身份格式标记 `Empty` | 不创建“可忽略任意数据”的规则；零长度与非零不同格式 | 空→非空必须重新解析且未支持时拒绝 | 缺失 | `empty_to_unknown_optional_rejected` |
| OptionalData 非空：Windows BCD / Linux loader 参数 / 厂商数据 | UEFI 仅定义传入加载镜像的字节；格式由生产者定义 | 未决 | 未获得完整正式字段定义与前后样本，不做全量比较或全量忽略 | 当前一律 UnsupportedFormat，包括看似文本、常见魔数和 GUID | 缺失 | `unknown_optional_data_rejected` |

没有任何身份变换通过真实样本 gate。拟允许的 description 改名、hidden 改变也须分别提供结构合法的正例与结构破坏/目标改变的反例。不得用手工变更真实文件来冒充“正常更新前后”证据。设备前缀、几何字段、路径规范化、OptionalData 待决意味着 CanonicalIdentity 的最终序列化尚未冻结。

## 支持格式与正向归类证据

| 输入/证据 | 当前研究结果 | 来源与反例 |
|---|---|---|
| 单实例短路径 HD(GPT GUID)+单绝对 FilePath+EndEntire、空 OptionalData | 候选支持轮廓，尚未通过样本门槛 | UEFI §3/§10；同一 GUID 克隆到多个分区时固件仍可能任选，不能保证最终 OS |
| 多实例、多 FilePathList 元素、网络、USB、vendor、完整未知前缀、默认回退文件 | UnsupportedFormat（暂定保守范围） | UEFI 允许多种解析路径；缺少可验证唯一目标语义 |
| `\EFI\Microsoft\Boot\bootmgfw.efi` + 已支持结构 | 将来 `Known(Windows)` 规则候选；现在 NeedsConfirmation | BCDBoot 官方目录资料；文件可被替换、BCD 可转向其他链，路径不是最终 OS 的证明 |
| `\EFI\systemd\systemd-bootx64.efi`、GRUB、shim 名称/路径 | NeedsConfirmation | 引导管理器可提供多个 OS；不能因为 Linux 项目生产 loader 就推断其最终 OS |
| 名称含 Linux/Arch/Ubuntu/Windows、唯一候选、不是 Windows | NeedsConfirmation | 无正向格式契约；重命名、恢复工具和其他 OS 是反例 |
| 人工表达 Windows/Linux + helper 独立验证成功 | 归类记录可配置为对应 Os；不是自动 Known 规则 | 用户补充 OS 语义，不放宽结构/格式/身份验证 |

对结构受支持对象的分类结果类型固定为 `Known(Os)` 或 `NeedsConfirmation`。自动规则启用表目前为空，至少一个真实 Windows/Linux 对照样本并不足以证明普适白名单；每条规则还须反例与唯一性检查。两个 Known(相同 Os) 候选仍请求选择。

## 真实样本采集门槛

未读取 `/sys/firmware/efi/efivars`，未运行 efibootmgr、bootctl、bcdedit、pkexec、sudo 或任何重启 API。以下是向 controller 提交的**待单独授权**只读命令，不是已执行记录。文件内容可能含设备 GUID、描述和参数，先私人保存，匿名化审查后才提交。

Linux 可在一个系统中获取同台固件的 Windows 与 Linux Boot#### 原始项；OS 标签必须由提供者说明，不能从 description 猜测。最低请求仅列出全局 GUID 下 Boot####、BootOrder、BootCurrent、BootNext，输出包含文件名、原始 SHA-256、Base64（保留四字节前缀），不写源文件。命令的 sudo 是权限请求范围，当前未获执行授权：

```sh
sudo /usr/bin/bash -c '
shopt -s nullglob
for sample in /sys/firmware/efi/efivars/Boot[0-9A-F][0-9A-F][0-9A-F][0-9A-F]-8be4df61-93ca-11d2-aa0d-00e098032b8c /sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c /sys/firmware/efi/efivars/BootCurrent-8be4df61-93ca-11d2-aa0d-00e098032b8c /sys/firmware/efi/efivars/BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c; do
  [ -f "$sample" ] || continue
  /usr/bin/basename "$sample"
  /usr/bin/sha256sum -- "$sample"
  /usr/bin/base64 --wrap=0 -- "$sample"
  printf "\n"
done
'
```

采集自身不是原子快照；再次只读采集并比较摘要，不一致则记录并拒绝作为同一时刻快照。固件来源需提供厂商/型号/版本（可人工填写，避免额外读取范围），时间和启动 OS 实际版本。读取失败须保留错误，不把失败当缺失。哈希与后续读取之间也有竞态，导入时须重算 Base64 解码内容哈希。

Windows 提供者可在已授权的管理员 PowerShell 中运行以下**辅助元数据**命令；其文本不能代替 EFI_LOAD_OPTION 二进制或 attributes：

```powershell
Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture,BiosManufacturer,BiosName,BiosVersion
bcdedit.exe /enum firmware /v
```

本任务禁止写生产代码，仓库也没有已审查的 Windows 原始变量采集器，因此不虚构可运行的导出命令。Windows 原始 API 样本另需明确授权制作/审查只读采集器：仅启用 SeSystemEnvironmentPrivilege，调用 GetFirmwareEnvironmentVariableExW 读取 BootOrder∪BootCurrent∪BootNext 及关联 Boot####，导出 out attributes + 原始 payload。该步骤当前未完成，Windows API 封装验收不能由 Linux 样本替代；Linux 采集仍可提供 Windows 启动项的真实格式样本。

正常更新配对须来自用户本来要执行的 OS/引导器更新，或已经留存的前后档案。本任务不请求执行更新、重建条目或重启。每组记录同机/同目标证据、采集 OS、更新组件精确版本、更新事件时间、两次原始摘要。至少 Windows loader 与 Linux 实际 loader 各一组。

匿名化在副本进行：GUID 采取同一数据集内一致的一一映射，保留 GUID 布局和相等关系；不修改节点边界、属性、路径、OptionalData。确需处理 UTF-16 描述时重新计算长度并明确标记加工步骤；这种修改不能充当自然更新证据。保留原始摘要（私有）和公开副本摘要，转换清单与 pair_id；不能证明结构保持时不公开该夹具。每个允许变换须有正反例，人工负例单独标 `synthetic-derived`，绝不计入真实更新门槛。
