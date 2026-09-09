# UEFI identity 研究契约（1S READY_FOR_REVIEW；Task1 BLOCKED）

首次官方核对日期2026-09-08，样本证据日期2026-09-09。初稿无样本，后经授权在Arch普通权限取得2个私有真实启动项，用户确认对应Arch Linux/Windows11；两次相同，更新配对0、公开fixture0。opaque精确策略已批准，Linux-first独立审查Approved后用户条件授权生效。2026-09-10按用户指定的保守范围收敛本表与 [共享/Linux前置契约](shared-linux-prerequisites.md)：1S.parse/1S/1L均READY_FOR_REVIEW，不自行标通过；1W仍缺原生证据，Task1总体BLOCKED。公开原文/更新配对不是strict exact门槛，1W不代替Core/Linux自身前置。

本表属于1S，替代先前拟定/未决的当前态表述，研究历史保留。完整字面字段/版本/序列化与测试名在共享契约§2；1S.parse验证表在§1，可独立审查后供Task2。未知节点可解析不代表identity支持；Task3必须等完整1S审查通过，本页READY不是实施完成或实机验收。

## 来源和解释边界

- [UEFI 2.10 §3.1.2–3.1.3、§3.3](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html)：load option、启动变量、OptionalData 和短设备路径语义。
- [UEFI 2.10 §10.3、§10.3.5.1、§10.3.5.4](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html)：节点边界、GPT/MBR 签名、路径拼接。
- [Linux efivarfs](https://docs.kernel.org/filesystems/efivarfs.html)：磁盘文件前四字节是小端**变量属性**；之后才是变量值。该在线页面未标明固定内核发布版本，不能用其渲染日期冒充版本。
- [Microsoft BCDBoot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11)：Windows EFI 安装目录、NVRAM 条目和 BCD 的关系。没有据此得到 OptionalData 的完整二进制稳定性契约。

以下设备路径/属性拒绝策略是BootHop的保守支持范围选择，不代表UEFI禁止其他合法格式。`UnsupportedFormat` 是外层结构/设备路径或独立有效性规则不受支持；未知OptionalData内部语义不单独触发它。`NeedsConfirmation` 是结构受支持但OS证据不充分，不能混淆；opaque策略不新增自动分类。

## 字段表

表中身份归属为本次保守契约，等待独立审查而非等待自然更新；测试名均待实施，没有声称已存在/运行。样本“私有2项”只说明已观察字段，不证明普适稳定性；OS标签来自用户确认，不是名称/路径推断。

| 字段 | 格式来源 | 是否身份 | 规范化方法 | 是否独立验证 | 样本 | 回归测试名 |
|---|---|---|---|---|---|---|
| Boot#### 编号 | UEFI §3.1.1，四位大写十六进制 UINT16 | 否，仅定位 | 解析为 u16；不追随其他编号 | 原编号存在、当前值可读 | 私有2项；缺删除对照 | `missing_original_id_stops` |
| 节点 type/subtype/length、顺序、结束节点 | UEFI §10.3 | 是：有序完整结构 | 全部字段精确保留；不以未知节点哈希替代支持 | 恰好单元素/单实例HD+FilePath+EndEntire，长度/终止有效 | 私有2项均此结构；synthetic待实施 | `short_gpt_filepath_supported`、`extra_path_rejected` |
| 硬件/ACPI/消息节点前缀 | UEFI §10.3 | 不支持输入 | 不删除、不重排、不折叠完整路径 | 一律UnsupportedFormat | 无需支持此范围 | `unknown_prefix_rejected` |
| HD分区格式/签名类型 | UEFI §10.3.5.1 | 是 | GPT=2、GUID=2固定保留，拒绝MBR/无签名 | HD长度42、分区号非零、16字节签名非全零 | 私有2项GPT/GUID | `hd_all_fields_roundtrip`、`mbr_or_unsigned_rejected` |
| GPT UniquePartitionGuid、分区号 | UEFI §3.1.2、§10.3.5.1 | 是 | 16字节UEFI原布局与u32精确比较，不变端序/转文本 | 重复canonical候选显式歧义；不声称核对实际磁盘GUID唯一 | 私有2项；标识不公开 | `partition_guid_change_rejected`、`partition_number_change_rejected` |
| 分区起始LBA、大小 | UEFI §10.3.5.1 | 是，全部保留 | u64精确比较，不忽略移动/扩容；未来忽略差异才需更新证据 | 大小非零，start+size无溢出；不读取/验证实际GPT | 私有2项；无自然移动对照 | `partition_start_change_rejected`、`partition_size_change_rejected`、`partition_range_overflow_rejected` |
| FilePath UTF-16路径 | UEFI §10.3.5.4 | 是 | 单绝对路径，原码元+固定NUL/节点长度；不NFC/折叠/拼接/斜杠替换 | 有效UTF-16、恰一个末尾NUL，拒绝相对、`.`/`..`、连续/末尾分隔符、仅根、正斜杠 | 私有2项单绝对路径；原路径不公开 | `absolute_unicode_path_preserved`、`loader_path_change_rejected`、`invalid_utf16_path_rejected` |
| 多FilePath节点/多实例/多列表元素 | UEFI §10.3、§3.1.3 | 不支持输入 | 不拼接/合并任何节点 | UnsupportedFormat；通用parser可表示不等于支持 | 无需支持此范围 | `split_path_not_silently_normalized`、`multi_instance_rejected`、`extra_path_rejected` |
| Description | UEFI §3.1.3 | 否 | 只显示；合法改名不改变身份；不以名称分类 | 有效UTF-16和NUL边界；空允许，显示转义控制字符 | 私有2项；synthetic改名待实施 | `valid_description_change_preserves_identity`、`malformed_description_rejected` |
| EFI_LOAD_OPTION.Attributes | UEFI §3.1.3，值内u32 | 否，独立执行验证 | 仅0x1或0x9：ACTIVE必需，HIDDEN可选，CATEGORY_BOOT=0 | 每次验证，APP/保留位/FORCE_RECONNECT/未激活拒绝 | 私有2项均1 | `hidden_change_preserves_identity`、`inactive_target_rejected`、`reserved_load_attribute_rejected` |
| UEFI变量attributes | UEFI §3.3；Linux前缀/Win32 out参数 | 否，独立存储验证 | Boot####/BootOrder/BootNext恰7，BootCurrent恰6 | 未知认证/附加位均拒绝；不混淆load属性 | 私有Boot项7；Next不存在；无Win32实证 | `variable_attributes_not_load_attributes`、`unexpected_variable_attributes_rejected` |
| FilePathListLength | UEFI §3.1.3，u16 | 是，结构派生字段 | 显式保存，必须等于三节点长度之和；不作总哈希 | 校验description/path/OptionalData边界和记录派生一致性 | 私有2项 | `path_list_length_overflow_rejected`、`bad_digest_or_derived_length_corrupt` |
| OptionalData 空值 | UEFI §3.1.3；已批准opaque修订§2 | 是：OpaqueExactV1 | byte_length=0 + SHA-256(empty)，完整32字节摘要；无忽略路径 | 外层边界有效；空/非空转换失配，停止switch后须主动重新确认configure | 用户确认的Arch私有样本为空；实现测试未开始 | `empty_optional_sha256_vector`、`opaque_exact_change_rejected` |
| OptionalData 非空：Windows / Linux loader / 厂商数据 | UEFI仅定义传入加载镜像的剩余字节；已批准opaque修订§2 | 是：OpaqueExactV1 | 完整原始字节长度+SHA-256；不删NUL/尾部、不重编码/折叠/抽取子集；未知非UTF-16同样适用 | 先验证外层/设备路径/attributes；长度或摘要变化停止switch，须主动重新确认OS并授权configure；不证明内部语义安全 | Windows私有样本136字节，内部语义仍opaque；自然更新对照仅未来放宽所需 | `opaque_non_utf16_can_register`、`opaque_exact_change_rejected` |

本轮无宽松路径/参数变换：结构字段全部精确保存比较，description/HIDDEN仅显示但每次独立验证。完整序列化为CanonicalIdentity版本1，精确字面字段见共享契约§2.1；OptionalData逻辑组件为OpaqueExactV1。description改名/hidden变化的正反用例列在§2.2，synthetic待实施不冒充自然更新。所有契约READY_FOR_REVIEW，审查通过后才供Task3实现；更新配对仅约束未来放宽。

组件种类/版本、算法、长度和完整32字节摘要须显式持久化，摘要为规范64位十六进制；未知记录/组件版本或算法fail closed且不可普通configure覆盖，损坏/错误摘要长度也拒绝、不等于Missing。configure从同一读取buffer计算结构字段与组件，switch不接受GUI摘要，任何失配不得WriteNext/Reboot/SaveRecord或自动重登记。可信记录/缓存/日志不存原始OptionalData，指纹不默认公开。相等判断依赖SHA-256抗碰撞假设，不证明语义、最终OS或相同路径二进制/BCD不变。

Windows非空OptionalData的官方依据、可观察布局和已批准精确策略见 [windows-optionaldata.md](windows-optionaldata.md)。用户的OS确认补充了本机样本标签，不能代替生产configure的结构检查，也不能直接启用自动Known规则。

## 支持格式与正向归类证据

| 输入/证据 | 当前研究结果 | 来源与反例 |
|---|---|---|
| 单实例短路径HD(GPT/GUID)+单绝对FilePath+EndEntire、任意有界OptionalData（含空） | 当前支持契约，READY_FOR_REVIEW；不宣称生产已验收 | UEFI §3/§10及opaque修订；同GUID克隆仍不能保证最终OS |
| 多实例、多FilePathList元素、网络、USB、vendor、未知前缀、仅FilePath/无明确FilePath的默认回退 | UnsupportedFormat | 规范允许不等于产品支持；不推断不受支持结构的唯一目标 |
| `\EFI\Microsoft\Boot\bootmgfw.efi` + 已支持结构 | 将来 `Known(Windows)` 规则候选；现在 NeedsConfirmation | BCDBoot 官方目录资料；文件可被替换、BCD 可转向其他链，路径不是最终 OS 的证明 |
| `\EFI\systemd\systemd-bootx64.efi`、GRUB、shim 名称/路径 | NeedsConfirmation | 引导管理器可提供多个 OS；不能因为 Linux 项目生产 loader 就推断其最终 OS |
| 名称含 Linux/Arch/Ubuntu/Windows、唯一候选、不是 Windows | NeedsConfirmation | 无正向格式契约；重命名、恢复工具和其他 OS 是反例 |
| 人工表达 Windows/Linux + helper 独立验证成功 | 归类记录可配置为对应 Os；不是自动 Known 规则 | 用户补充 OS 语义，不放宽结构/格式/身份验证 |

对结构受支持对象的分类结果类型固定为 `Known(Os)` 或 `NeedsConfirmation`。自动规则启用表目前为空，至少一个真实 Windows/Linux 对照样本并不足以证明普适白名单；每条规则还须反例与唯一性检查。两个 Known(相同 Os) 候选仍请求选择。

## 真实样本采集门槛

时间线：2026-09-08初稿没有读取固件。2026-09-09用户授权后，controller 使用已审查的独立Python研究采集器，在Arch普通权限下读取允许的固件变量并仅保存本地私有副本，未使用root、未运行固件工具、未写EFI或重启。其后分析只读本地副本；OS标签由用户明确确认。当前授权不包含追加采集、Windows操作、更新或重启。

下列命令保留为初稿的**历史提案**，并非本次执行方式，不构成继续执行的授权。文件内容可能含设备标识、描述和参数，必须先私人保存；公开manifest只记录计数，真实内容在逐字段匿名化审查前不得提交。

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

本任务禁止写生产代码，仓库也没有已审查的 Windows 原始变量采集器，因此不虚构可运行的导出命令。Windows 原始 API 样本若未来继续，另需明确授权制作/审查只读采集器：仅启用 SeSystemEnvironmentPrivilege，调用 GetFirmwareEnvironmentVariableExW 读取 BootOrder∪BootCurrent∪BootNext 及关联 Boot####，导出 out attributes + 原始 payload。该步骤当前未完成、未获本轮执行授权，Windows API 封装验收不能由 Linux 样本替代；已取得的 Linux 副本仅支持 Windows 启动项格式研究。

正常更新配对现仅是未来放宽/归一化研究要求，不是MVP strict exact门槛；须来自用户本来要执行的OS/引导器更新或既有前后档案。本任务不请求更新、重建条目或重启。未来研究至少Windows loader与Linux实际loader各一组，私有记录同机/同目标证据、采集OS、组件精确版本、事件时间及两次原始摘要。

匿名化在副本进行：GUID 采取同一数据集内一致的一一映射，保留 GUID 布局和相等关系；不修改节点边界、属性、路径、OptionalData。确需处理 UTF-16 描述时重新计算长度并明确标记加工步骤；这种修改不能充当自然更新证据。保留原始摘要（私有）和公开副本摘要，转换清单与 pair_id；不能证明结构保持时不公开该夹具。每个允许变换须有正反例，人工负例单独标 `synthetic-derived`，绝不计入真实更新门槛。
