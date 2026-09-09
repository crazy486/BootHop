# Windows OptionalData：已观察布局与未证实语义

核对日期：2026-09-09；2026-09-10仅同步Linux-first门槛。Task1整体 **BLOCKED**，不是全平台统一停工状态：1S约束共享身份，1L约束Linux，1W实证只阻Windows分支及最终跨平台声明；修订审查通过后按各自前置放行。本页只公开通用结构与证据等级，不包含私有启动项编号、描述、设备路径、GUID、完整参数或原始字节。历史研究使用授权副本与官方资料；本轮无采样、Windows操作、提权或引导器修改。

## 可确认的事实

本机2个真实启动项已由用户分别确认对应 Arch Linux 与 Windows 11；语义标签和原始数据仅保存在私有目录。两项均为短 HD(GPT/GUID)+单绝对FilePath+EndEntire 路径，变量属性为7，load-option属性为1。Arch项的OptionalData为0字节；Windows项为136字节。每项两次连续读取完全一致，原始文件哈希、长度与采集报告一致；这不是正常更新前后对照，也不是Windows API读取证据。

Windows私有副本按 EFI_LOAD_OPTION 的description终止符与FilePathListLength确定OptionalData边界，不从显示字符串截取。下表偏移均相对于该136字节OptionalData起点；这是**单个样本的观测分区**，不是已确认的Microsoft结构定义。

| 偏移 / 长度 | 可观察形状 | 证据与限制 |
|---|---|---|
| 0 / 8字节 | ASCII `WINDOWS` 后接NUL | 固定文字形状存在；不能仅凭标记确定版本或信任格式 |
| 8 / 12字节 | 参数段前的二进制区域，可按三个u32槽位观察 | 未找到官方字段定义；不将其命名为version/length/offset，不推断保留位或忽略规则 |
| 20 / 98字节 | UTF-16LE `BCDOBJECT=`、花括号GUID形状、NUL终止 | 本地工具仅确认形状和边界；GUID值不公开；可解码不等于整块数据是文本 |
| 118 / 18字节 | 参数终止后的二进制区域；末端4字节匹配UEFI EndEntire节点形状 | 未证明该区域就是设备路径、补齐或无关尾部，不解释为可丢弃padding |

样本中的头部槽位数值仅记录在私有分析文件。本轮没有通过猜测长度字段、重排、删除尾部、改写参数、执行bootloader或反编译来验证其语义。

## 官方资料能支持什么

| 官方来源 / 实际使用版本 | 可支持的结论 | 不能从该来源推导的结论 |
|---|---|---|
| [UEFI 2.10 §3.1.3](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html)（初次全文核对2026-09-08） | OptionalData是EFI_LOAD_OPTION剩余字节，传给加载镜像；其长度由结构边界确定 | Windows专有字段布局、BCDOBJECT参数消费行为、正常更新可变字段 |
| [UEFI 2.10 §10.3](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html) | 标准设备路径节点的形状及终止节点 | OptionalData中相同形状字节必定拥有设备路径语义 |
| [Microsoft BcdObject](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bcd/bcdobject)（2018-05-30文档，2026-09-09核对） | BCD对象以GUID标识，GUID在对应store内标识对象，object type区分boot manager/loader等 | NVRAM OptionalData中的GUID一定对应特定store/OS；这136字节结构的二进制契约 |
| [Boot Options Identifiers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/boot-options-identifiers)（2026-09-09核对在线版） | BCD条目标识与boot manager/default/current等别名语义 | 参数名或单个标识证明最终Windows安装、稳定身份或安全忽略其他字段 |
| [BCD System Store Settings for UEFI](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcd-system-store-settings-for-uefi?view=windows-11)（Windows11视图，页面2021-10-08，2026-09-09核对） | Boot manager和Windows loader是不同BCD对象；device/path设置、默认项和多loader配置影响启动选择 | NVRAM启动项不变即可保证BCD未改变或最终OS一致 |
| [BCDBoot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11)（Windows11视图，2026-09-09核对） | Windows安装/维护涉及BCD和固件启动项 | 某个OptionalData字段在所有正常维护中不变或可忽略 |

使用通用术语查询Microsoft Learn、Microsoft公开仓库和UEFI资料，未将任何私有GUID、完整参数、路径或原始数据发送到搜索服务。本轮没有找到能正式规定上述完整二进制结构和更新稳定性的官方契约；这是本轮核对结果，**不是**对所有官方资料都不存在该定义的证明。搜索中出现的论坛、第三方逆向实现和二手样本没有作为批准依据。2026-09-09重开部分UEFI网页出现403，仍以此前已读取的2.10正文为依据；不把失败页面当新版本核对完成。

## identity处理决定

历史：本页初稿因完整字段语义未知而将非空OptionalData一律判为UnsupportedFormat，并把精确指纹仅列为待裁定候选。该产品策略已被[用户批准的opaque修订](../superpowers/specs/2026-09-09-opaque-identity-amendment.md)替代；内部语义依旧未知，不是已经解码成功。

当前已批准：所有MVP OptionalData（包括空和未知非UTF-16二进制）统一使用 `OpaqueExactV1 { algorithm: Sha256, byte_length: u64, digest: [u8; 32] }`。外层完整解析确定边界，从同一读取buffer计算结构化identity及完整原始字节长度+SHA-256；不截断摘要、剥NUL、重编码、删尾部或提取BCDOBJECT子集。空值也使用长度0与SHA-256(empty)。结构/设备路径/attributes规则不放宽；此组件不能替代它们，不能证明内部格式安全或最终OS正确。

受保护记录显式保存组件种类/版本、算法、长度和规范64位十六进制的完整32字节摘要，不保存原始OptionalData；GUI缓存/普通日志同样禁止原文，指纹不默认公开。未知记录/组件版本或算法fail closed，普通configure不能覆盖；损坏摘要也拒绝、不当作Missing。内容一致是长度与完整SHA-256的工程判断，依赖抗碰撞假设。

任意长度/摘要或结构化identity变化均在BootNext修改及重启前停止，不自动保存/跟随编号/configure。用户必须主动重新选择并确认OS，经正常UAC/polkit授权后由configure建立新基线；正常未变化切换无额外确认。未知组件与普通失配区分，不提供普通configure恢复入口。

完整精确策略已获批准，但没有新增宽松变换或自动归类规则。`WINDOWS`标记、UTF-16、GUID形状、用户标签、连续两次相同均只支持有限观测。未来若要语义归一化或容忍更新变化，须另定版本、取得正式依据/正反证据/自然更新配对并批准；配对不再阻止MVP strict exact。完整结构字段契约是1S缺口；Windows原生只读API是1W缺口，不能用后者阻止前置已满足的共享/Linux实现，也不能从前者或fake通过宣称Windows可用。

## 证据状态

| 研究要求 | 当前状态 |
|---|---|
| 本机Windows/Arch真实启动项与用户OS确认 | 已取得私有证据，各1项 |
| 外层UEFI结构、两类attributes、OptionalData边界 | 已有官方格式依据和本机观测 |
| 136字节内部形状分区 | 已私有检查；公开仅非敏感布局 |
| Windows OptionalData正式字段语义与更新稳定性 | 未完成，opaque；strict exact不要求解码 |
| OpaqueExactV1完整精确策略 | 已用户批准；不等于完整生产identity契约完成 |
| 同目标正常更新前后Windows/Arch配对 | 各0组；仅未来放宽/归一化gate，不阻MVP strict exact；本轮无采集/更新 |
| 完整结构字段契约、支持规则和正反验证 | 已按授权保守范围收敛，1S/1S.parse READY_FOR_REVIEW；测试名不是执行结果，须审查后放行对应任务，见shared-linux-prerequisites |
| Windows原生GetFirmwareEnvironmentVariableExW权限/out attributes/payload/错误语义 | 1W未完成，阻Windows分支和最终跨平台声明，不阻自身前置已满足的Core/Linux；Arch副本不替代，需另获只读授权；安全不可观察错误明确限制并fake覆盖 |
| UAC/会话/正常重启与BootNext写入实测 | 未完成，属于后续单独授权验收，不为补只读gate执行 |
| 公开、匿名化审阅后的真实fixture及回归样本 | 尚未发布，不是MVP硬gate；私有真实证据有效，普通CI用synthetic |
