# BootHop Linux-first：按证据拆分实施门槛

状态：独立规格/质量审查Approved，用户条件授权已生效，按分层前置继续SDD；不需要再次整体批准。2026-09-10。后续技术契约已独立审查：1S.parse/1S APPROVED（66eaf9f）、1L APPROVED（600aa4d），不是由本页调度审查自动放行。本轮仅状态文档同步，不访问固件、不提权、不升级、不执行真实写入或重启。

审查记录：调度修订独立规格与质量审查均Approved，无缺陷；随后技术子门槛按上列证据分别批准，1W仍BLOCKED。实施/修复/测试审查进度以manifest及controller ledger为准，契约审批不能替代实现验证。

## 1. 方案与范围

采用 shared / Linux / Windows 独立证据门槛：Windows原生证据只阻Windows实现分支与最终跨平台声明，不阻已被规范、Arch私有样本及opaque契约充分约束的Core/Linux。整体Task1不能因Linux子项完成而标完成。

| 方案 | 取舍 |
|---|---|
| 按证据拆分门槛（采用） | Core/Linux可独立推进，Windows仍须实证；每项报告明确平台和证据等级 |
| 全部任务等待Windows实证 | 保留旧全局阻塞，但把不相关平台依赖加给纯解析/Linux；本修订替代 |
| Windows用stub/fake成功占位 | 会把契约模拟误当平台可用；禁止 |

本修订只调整依赖与交付顺序，不裁定新的结构字段算法，不放宽opaque exact、设备路径、attributes、未知记录/组件/算法fail closed、主动重新确认configure或并发/Unknown规则。Windows启动项由Arch读取，只能作UEFI输入格式/用户OS标签证据，不等于Windows操作系统API实证。

## 2. Task1子门槛与退出条件

| 子门槛 | 必须完成并独立审查的产物 | 当前状态 |
|---|---|---|
| 1S：shared prerequisites | 完整结构字段/支持范围/独立验证契约，样本来源与正反验证表，opaque组件/记录版本/分类规则一致性 | APPROVED（66eaf9f），共享契约§2；不等于identity实现测试通过 |
| 1S.parse：1S内可单独放行的纯解析契约 | 有界UEFI解析验证表，覆盖以下条目，明确每项输入边界、结果和synthetic测试名；不依赖identity字段归属 | APPROVED（66eaf9f），共享契约§1；Task2实现证据独立记录 |
| 1L：Linux contract prerequisites | efivarfs读取/属性/错误/限制，Linux存储锁、pkexec/IPC、logind非强制重启及阶段语义的契约和fake验证清单；区分官方/Arch观察/待验收 | APPROVED（600aa4d），共享契约§3；真实集成/写入/重启仍PENDING |
| 1W：Windows evidence | Windows实际GetFirmwareEnvironmentVariableExW读取、权限、out attributes、payload及错误语义证据；安全不可观察的错误明确限制并fake覆盖 | BLOCKED：未取得Windows原生只读实证 |

调度修订时1S的具体剩余清单是：节点/前缀与单实例；GPT标识/分区号；LBA/大小；FilePath数量/绝对路径/编码/规范化；description合法性；两类attributes；完整序列化/正反用例；Known不足时空表/NeedsConfirmation。本调度修订没有冻结算法；其后用户指定保守三节点范围，在 [共享/Linux前置契约](../../research/shared-linux-prerequisites.md) §2逐项收敛并于66eaf9f获独立批准，替代历史待审状态，不把自然更新配对重新设为strict exact前提。

1S.parse验证表必须覆盖：6字节固定头的小端读取和截断；description的UTF-16终止/编码与边界；FilePathListLength有界消费；设备路径节点最小长度、溢出、终止和实例边界；剩余OptionalData完整保留、允许空和非UTF-16；解析失败不得产出有效目标。纯解析能表示未知节点不代表identity支持，目标验证仍拒绝不在白名单内的设备路径。验证表审查通过可单独启动Task2，不必等待1S其余identity决定或1W。

1L不要求为了实施门槛提前触发真实BootNext/重启：相关写入/重启/授权行为先由已核对契约和fake清单约束，真实行为属于后续单独授权验收。1W只在另获Windows只读操作授权后采证，不通过写API、重启或制造系统变化补错误样本。Contract/fake、交叉编译或Linux成功均不能把1W标通过。

## 3. 精确依赖与建议调度

本修订及上列共享/Linux契约审查均已通过；各实施项当前进度以manifest及controller ledger为准。表中“完成”仍指相应产物与规定审查均通过，不是只有代码存在，也不能从一个任务完成推断其他任务完成。

| 任务 | 必需前置 | 交付边界 |
|---|---|---|
| 2 | 1S.parse | 纯解析和synthetic隔离测试，不冻结identity |
| 3 | 2、1S | 完整canonical identity与目标验证 |
| 4 | 3 | 共享记录和版本错误 |
| 5 | 4 | 共享fake状态机 |
| 6L | 5、1L | 共享存储契约/fake基座、Linux受保护存储与锁 |
| 7 | 6L | Linux adapter，普通测试仅fake |
| 9L | 5、6L、7 | 共享协议/分发契约和Linux pkexec/管道客户端 |
| 10L | 9L | 平台无关GUI/controller及Linux接线 |
| 11L | 10L | Linux开发构建/打包、隔离CI和待验收文档，非最终跨平台发布 |
| 6W | 5、6L、1W | Windows受保护存储/ACL与锁；共享存储契约沿用6L定义 |
| 8 | 6W、1W | 仅Windows firmware/reboot adapter |
| 9W | 8、9L、1W | Windows UAC/namedpipe和共享协议集成 |
| 10W | 9W、10L、1W | Windows GUI接线、Windows专属行为验证 |
| 11W | 10W、11L、1W | Windows MSI/CI/发布材料，不自动宣称最终验收 |
| 最终双向/跨平台验收与声明 | 11L、11W、1S、1L、1W，以及另行授权的实机写入/重启和GUI/安装验收通过 | 每方向BootOrder前后不变、阶段结果及人工目标OS观察；否则不得宣称完成 |

6W消费6L的共享契约产物，不复用Linux OS实现。建议主线先完成1S/1L证据收敛与审查，再2→3→4→5→6L→7→9L→10L→11L；允许1S.parse先独立审查后提前做2。Windows分支待1W通过，按6W→8→9W→10W→11W推进，同时遵守表中的共享产物依赖。

## 4. 不成功占位与报告边界

未实施Windows adapter/client/packaging时使用明确的编译目标隔离；不提供返回成功的stub、不注册假可用平台、不让Linux默认测试加载Windows或真实固件适配器。纯共享数据模型可以表达Windows/Linux的Os枚举；这不是平台可用声明。测试报告区分纯fake/编译、Linux开发产物、各平台实证和最终验收。

11L产物明确“Linux开发构建，Windows分支及双向切换未验收”；构建/安装包验证不授权安装到真实系统或执行切换。Windows未实现时GUI、README、支持矩阵不宣称双平台可用或从Windows返回Linux已完成；Linux下显示Windows目标语义也不证明实际启动成功。

## 5. 历史替代与验证

本修订仅替代主规格、计划和研究材料中“Windows原生API实证阻止所有后续任务”的全局调度规则。2026-09-09 opaque规则保留；旧全局gate历史由本文替代。Task1总体仍BLOCKED/1W缺实证；1S已按独立证据批准，identity消费者仍须满足全部任务依赖及实现审查，不由调度修订自动完成。

文档自审需检查：依赖表与各任务分支一致；2依赖1S.parse而3依赖完整1S；1W不出现在Core/Linux必需前置；Windows任务均有1W且无stub成功；manifest各子门槛与aggregate状态一致；JSON/关键词/差异检查通过，无私有原始样本内容。文档TDD不适用；本轮不声称任何生产测试或平台验收完成。progress ledger由controller维护。
