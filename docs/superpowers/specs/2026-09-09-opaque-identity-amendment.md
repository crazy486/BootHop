# BootHop identity 修订：结构化身份与 opaque exact-match

状态：已用户批准。2026-09-09。本文全部修订生效，替代此前非空未知 OptionalData 一律拒绝及正常更新配对阻止 MVP strict exact-match 的规则；其余研究门槛不因此解除，本轮不推进生产代码。

独立审查结果：规格符合，设计质量 Approved；未发现 Critical、Important 或 Minor 问题。其后用户明确批准全部修订。

2026-09-10调度补充：[Linux-first修订](2026-09-10-linux-first-amendment.md) 待独立审查通过后替代本文§4中Windows实证阻全部实施的旧范围，仅将其保留为1W/Windows分支及最终跨平台声明硬gate；不改变本文已批准的opaque身份规则。

## 评估与推荐

推荐采用结构化 canonical identity + opaque OptionalData 完整内容指纹。BootHop 的目标是确认当前启动配置与用户授权登记的目标一致，而非验证任意引导器参数的内部语义。将“不能解释参数”一律等同于“无法登记已有目标”，超出了这一目标；此前的拒绝策略是产品保守选择，并非 UEFI 对 OptionalData 的结构要求。

| 方案 | 收益 | 代价 / 决定 |
|---|---|---|
| 结构化身份 + opaque 完整指纹 | 不忽略未知参数；支持已确认目标的严格变更检测 | 任意 opaque 变化重新配置；推荐 |
| 非空未知 OptionalData 一律拒绝 | 无需接受未知参数作为基线 | 当前 Windows 样本无法登记；不推荐继续作为 MVP 全局要求 |
| 只保留可识别参数或忽略未知区 | 正常更新后可能更少失效 | 缺语义依据会漏检目标变化；拒绝 |

UEFI 将 OptionalData 定义为传给加载镜像的剩余二进制数据；并不要求其为 UTF-16 或 Windows BCD 结构。[UEFI 2.11 Boot Manager §3.1.3](https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html)、[UEFI 2.10 Loaded Image](https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html)。SHA-256 为标准摘要算法；此处使用其抗碰撞假设作变更检测，不是签名、加密或语义验证。[NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)。

## 1. 保证范围与有效性

“合法 EFI_LOAD_OPTION”指外层结构解析通过：长度有界、description 终止/编码符合既有规则、FilePathListLength 与实际边界一致、设备路径节点及终止结构有效、启动属性符合既有执行前置条件。设备路径仍使用明确支持的结构与验证规则；未知设备路径不能借 opaque OptionalData 模式绕过验证。

OptionalData 起点必须由完整外层结构解析计算，终点是本次读取的 payload 结尾。非空二进制中没有 UTF-16 终止符、含未知魔数或不可解码文本，本身不构成外层结构错误；BootHop 不将其解释为代码或执行它。

支持该模式只说明可以登记并比对这段不透明数据，不说明其内部格式安全、其语义正确、目标 OS 可启动或启动链未被篡改。用户 OS 确认、已有高置信度归类的证据标准均不改变；opaque 模式不新增自动分类规则。现有两条样本的 OS 归类来自人工确认。

## 2. 精确身份组件

canonical identity 继续包含有格式依据的结构化设备路径和已裁定稳定字段。只对 OptionalData 使用以下身份组件；禁止对整个 EFI_LOAD_OPTION 做总哈希来替代结构验证。

逻辑表示：`OpaqueExactV1 { algorithm: Sha256, byte_length: u64, digest: [u8; 32] }`。

- digest 严格为 `SHA-256(OptionalData完整原始字节)`，不截断摘要，不剥离NUL，不重编码，不大小写折叠，不删除尾部，不提取BCDOBJECT子集。
- 空 OptionalData 也使用长度0及空字节串SHA-256；空到非空、非空到空均失配，不另设“忽略”路径。
- 保存显式组件种类/版本、算法和长度。持久化可用规范的64位十六进制字符串表示32字节摘要；未知组件版本或算法、错误摘要长度、损坏记录均fail closed，不按旧规则降级。
- 整个受保护记录的未知/较新版本仍禁止普通 configure 覆写；未知身份组件同样按不支持的记录处理，不诱导用户通过普通重新配置覆盖。
- 所有MVP OptionalData一律使用该exact组件，包括看似已知的字段；未来语义模式需单独版本和批准，避免当前同一字节被不同路径解释。
- 不在受保护目标记录、GUI缓存或普通日志保存原始 OptionalData。指纹也不作为公开诊断默认输出；摘要不是保密机制，低熵数据仍可能被猜测。私有研究原文继续按既有授权保留。

长度与完整SHA-256相等被视为工程上的内容一致判断，依赖密码学抗碰撞假设，不能宣称数学意义上绝对证明字节相等。检测到任何长度或摘要差异即拒绝；不允许部分匹配或摘要前缀匹配。

## 3. configure / switch

configure 在受保护记录版本检查通过后，重新从固件读取合法的目标项，生成结构化identity及opaque组件，并原子保存。GUI不能提供可信digest。配置阶段的指纹与结构化字段必须来自同一读取buffer，不分别读取两次后拼接目标记录。

switch 从受保护记录获取目标，在原编号重新读取、完整解析并独立验证所有结构化字段和opaque组件。任何不一致返回目标失效，停止在BootNext修改和重启之前；不自动修改指纹、不追随编号、不自动执行configure。

opaque失配后用户必须主动进入重新配置，并重新确认目标OS语义，经过正常UAC/polkit授权后由configure建立新基线。不能因为显示名称不变就自动接受新参数；这不会给日常无变化的一键切换增加重复确认。

推荐失配文案：“目标启动配置已变化，请重新选择并确认目标。”不要显示“参数已损坏”“Windows不安全”等没有证据的结论。未知记录版本另用兼容版本/升级提示，不能混为可普通重新配置的目标失效。

记录能证明的只是登记时与当前读取的配置一致；外部程序在检查之后修改变量、相同路径上的引导器二进制/BCD存储变化等原有能力边界均保留。此修订不引入跨固件原子性承诺。

## 4. Task 1 与研究门槛调整

| 要求 | 批准此修订后的地位 |
|---|---|
| 合法外层UEFI/设备路径规则及真实本机样本 | 仍须完成结构字段表和验证依据；现有私有样本可作证据，不要求公开原文 |
| OptionalData完整内部语义 | opaque exact模式不要求理解；仍明确标为未解释 |
| Windows/Arch正常更新前后对照 | 不再是MVP strict exact-match实施硬门槛；保留为未来允许变化、归一化或降低误失效的研究证据 |
| 结构化字段的任何新宽松变换 | 仍须明确格式依据和正反测试；不能借本修订自动放宽 |
| Windows原生firmware API实机验证 | 需Windows实际GetFirmwareEnvironmentVariableExW、权限、out attributes、payload与错误语义证据，Arch采样不能替代；Linux-first修订审查通过后归1W，只阻Windows实施分支和最终跨平台声明，不阻自身前置已满足的Core/Linux |
| 固件写入/BootNext/重启真实验收 | 单独授权的后续验收，仍不能被普通测试触发；本修订不授权执行 |

Windows前置门槛限于单独获授权的只读原生API验证；不会为了补齐门槛执行SetFirmwareEnvironmentVariableExW、重启或主动制造系统变化。无法安全观察的错误分支明确记录限制，以fake覆盖，不能伪装实机证据。

本轮仅同步文档，不发起Windows读取或申请系统权限。opaque修订已获批，Task1不能直接标完成；当前结构字段缺口归1S、Linux契约核对归1L、Windows原生缺口归1W，按Linux-first修订分别审查放行。

## 5. 验证要求（全部普通测试使用fake或本地夹具）

- 标准SHA-256已知答案测试（含空输入）及完整32字节摘要序列化往返；使用成熟库，不自行实现哈希。
- 同一合法启动项重复生成组件一致；未知非UTF-16 OptionalData可登记为opaque，不因无法解码而拒绝。
- 在不破坏外层结构的前提下，对正文、尾部、NUL、追加/截断、单bit变化、空/非空转换检查失配；测试变体标明synthetic，绝不冒充正常更新证据。
- 外层截断、设备路径不支持或畸形时，即使digest碰巧匹配也必须拒绝；结构验证必须先于opaque组件比较。
- GUI篡改digest/编号无效；configure计算真实buffer指纹；switch失配后fake事件序列不得出现WriteNext/Reboot/SaveRecord。
- 未知记录/组件/算法版本阻止inspect/configure/switch的依赖操作；普通configure不能覆盖。
- 明确用户重新配置可替换已支持格式的旧基线，后续严格验证新基线；没有自动重新登记路径。
- 受保护记录、错误和GUI缓存没有原始OptionalData；正常更新可触发失效属于预期行为，不据此放宽比较。

## 6. 已批准修订的文档同步清单

使用writing-plans同步：主规格§5/§9/§10及Task1附录；实施计划Task1、3、4、5、9、10及全局门槛；identity字段表、windows-optionaldata研究结论、support-matrix、manifest与progress ledger。将“非空一律UnsupportedFormat”和“更新配对阻止全部后续任务”改为本修订的有限规则；ledger由controller维护。

保留研究历史：内部格式依旧未知，改变的是允许严格登记与比对的产品策略，不篡改为已经解码成功。manifest区分`opaque_exact_strategy_approved=true`与`production_identity_contract_approved=false`；前者获批不意味Windows门槛已通过或整个Task1完成，当前状态仍为BLOCKED。
