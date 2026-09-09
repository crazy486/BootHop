# Windows OptionalData：已观察布局与未证实语义

核对日期：2026-09-09。Task 1 状态 **BLOCKED**。本页只公开通用结构与证据等级，不包含私有启动项编号、描述、设备路径、GUID、完整参数或原始字节。研究仅使用经授权取得的本地副本和公开官方资料，没有再次读取固件、操作Windows、提权或更改引导器。

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

当前生产支持结论仍为 `UnsupportedFormat`：非空Windows OptionalData是 **opaque**，没有获批字段级算法。用户确认Windows11只补充目标OS语义，不能绕过此格式门槛。不能忽略OptionalData、不能仅提取BCDOBJECT GUID、不能把整个EFI_LOAD_OPTION或整块OptionalData无差别逐字节比较后声称稳定身份已经成立。

可审阅的保守研究候选有两类，但本轮均不启用：

1. 若未来取得正式结构依据，将已理解的对象选择字段纳入目标身份，并独立验证版本、长度、边界及影响执行的其他字段；只有获得真实正常更新正反对照的区域才允许变化。
2. 在正式语义仍不明确时，可以把未知区域的精确指纹作为**额外变更阻断条件**研究，任何变化要求重新研究；它不能单独证明初始格式安全、不能把UnsupportedFormat变为受支持，也不替代结构化identity。该候选会拒绝可能合法的正常更新；若要作为产品支持模式，须另作明确设计裁定，不在当前规则中暗中启用。

没有被批准的identity变换；字段级规则的正例/反例和正常更新前后配对均未满足。`WINDOWS`标记、UTF-16可解码、GUID形状、用户标签或连续两次相同，分别只能支持各自有限事实，不能叠加成尚未验证的格式白名单。

## 证据状态

| 研究要求 | 当前状态 |
|---|---|
| 本机Windows/Arch真实启动项与用户OS确认 | 已取得私有证据，各1项 |
| 外层UEFI结构、两类attributes、OptionalData边界 | 已有官方格式依据和本机观测 |
| 136字节内部形状分区 | 已私有检查；公开仅非敏感布局 |
| Windows OptionalData正式字段语义与更新稳定性 | 未完成，opaque |
| 同目标正常更新前后Windows/Arch配对 | 各0组；本轮不执行更新或追加采集 |
| 原生Windows API attributes/payload、UAC/会话/正常重启实验 | 未完成；Arch副本不替代Windows实机验证 |
| 公开、匿名化审阅后的真实fixture及回归样本 | 尚未发布；公开manifest仅记录私有证据计数 |
