# Windows → BootHop → Arch：保留普通 GRUB 菜单的一次性直达设计

日期：2026-09-29。状态：研究完成、设计提案待用户审阅；不是实现批准，不授权任何 EFI/GRUB/系统修改、固件写入或重启。

## Problem

普通开机必须保留用户现有的交互式 GRUB 菜单，让用户照常选择 Arch 或 Windows；从 Windows 使用 BootHop 切到 Arch 时，则希望固件这次直接进入 Arch，不停在 GRUB 菜单等待人工选择。日常 BootHop 切换仍应只设置一次性 `BootNext`，不改动 `BootOrder`。

现有批准的 BootHop 设计只设置已登记的启动项 `BootNext`，不创建/修复 `Boot####`，不修改 `BootOrder`。因此本文是明确的范围变更提案，不会静默改写既有规格。

## Current boot topology

- 用户此前确认 `Boot0000` 是 Arch 入口、`Boot0003` 是 Windows 11 入口；只读实机记录显示普通顺序为 `0000,0003`，当前 Linux 由 `Boot0000` 进入 GRUB。
- 当前 GRUB 配置显示交互式菜单，约 5 秒等待；Arch 的 kernel/initramfs 使用稳定文件名。`/boot` 位于 ESP。
- 研究代理只读观察到当前 Secure Boot 关闭。该事实仅适用于本次研究时的这台主机；未来 setup 必须实时检测，不能假设其他机器相同。
- 不在本规格中记录私有设备路径、EFI 原始数据或 UUID。

普通 BootHop 日常切换到 Windows 已通过实机验收；本文仅讨论反向路径的 GRUB 菜单体验。

本文只提出当前 Arch + GRUB 实机的可选集成，不扩大 BootHop 对其他 Linux 发行版或 bootloader 的支持承诺。未来 Windows production line 仍未完成；此文不表示 Windows → Arch 已可用。

## Candidate designs

### A. 全局隐藏 GRUB 菜单

通过 GRUB 全局 timeout/hidden 设置隐藏菜单。实现改动最少，不增加运行时组件、不需要 Windows 访问 Linux 文件系统或新建启动项，也不需要修改 `BootOrder`。

但它同样影响普通启动：普通 `Boot0000` 也不再呈现现有交互菜单，直接违反本需求。即使保留按键打断，也不是“普通开机仍显示现有菜单”。因此不采用。

### B. 复用 GRUB `grubenv` 的 one-shot marker

从 Windows 设 `BootNext` 到现有 GRUB 入口，再向 GRUB environment block 写入 `next_entry`/专用标记；GRUB 仅在标记存在时走无菜单路径，正常开机仍显示菜单。`saved_entry` 是持久默认值，不等价于一次性标记，故不适用。

GRUB 有 one-shot `next_entry` 语义，但它是 GRUB 自身状态，不是 UEFI `BootNext`。本机的 GRUB 配置即使消费 `next_entry` 仍配置菜单等待时间；需要额外改造 GRUB 配置。Windows 端还要定位并安全写入 ESP 上的 `grubenv`，每天需协调两个非事务状态（`BootNext` 与 marker），并处理 GRUB 环境块格式、并发、失败回滚和“marker 未消费”残留。它不必写 ext4，但会让 Windows helper 写共享 ESP 文件，并且日常不再是“只写 BootNext”。实现/维护复杂度中等，且和已批准平台边界冲突；不采用。

### C. 专用 BootHop Arch EFI 启动目标

普通 `Boot0000` 和现有 GRUB 配置完全不动。首次明确 setup 为 Arch 准备一个固定路径、可直接启动 Arch 的 EFI 目标，并建立专用 `Boot####`。Windows 的 BootHop 配置此项为 Linux 目标。日常 Windows → Arch 只设置 `BootNext = BootHop Arch entry`；固件启动它时不进入原 GRUB 菜单。

专用项不能只是复制一个标签、仍指向同一 GRUB EFI 文件和同一配置：那样仍会显示原 GRUB 菜单。可实现载体需在实施前由当前 Arch 配置确认。当前研究首选固定路径 UKI，由 Arch `mkinitcpio` preset 在 kernel 更新时自动重建；这是一个更新系统维护的合并 EFI 镜像，不是手工维护的独立 kernel 版本副本。单独构建的 GRUB EFI image + 直达配置是备选，但会增加 GRUB image、配置和 GRUB 更新重建/签名维护。裸 kernel EFI stub 也可直启，但官方说明要求放在固件可读的 ESP 上并按 EFI 可执行文件方式部署，且需要将 initrd 路径与 kernel command line 放进 EFI load options；当前稳定路径/扩展名/实机行为尚未完成核对，不作为当前首选。

## Recommended design

采用 **C：专用 BootHop Arch Boot####，目标为固定路径、由 mkinitcpio 更新流程重建的 Arch UKI**。保持现有 `Boot0000`、其 GRUB 程序、GRUB 配置和菜单不变。UKI 路径使用稳定名称，不带 kernel 版本号；preset 同时包含当前 Arch 所需 kernel、initramfs、microcode（如有）及经确认的 kernel command line。

可靠持久化和 Windows 首次发现有一个必须公开接受的条件：**首次 provision 将新 BootHop ID 追加到当前 `BootOrder` 的末尾，原有项目及其相对顺序保持不变；日常 Switch 不再写 BootOrder。**理由见下文 UEFI 生命周期。若用户要求连首次安装也绝不改变 BootOrder，则 C 只能作为特定固件的实验性方案，不能作为跨固件保证；应停止实现，不得静默退回不可靠 orphan-entry 方案。

追加到末尾使普通开机仍先启动原 `Boot0000` 并显示 GRUB 菜单；BootHop one-shot 则因 `BootNext` 优先级而直达 UKI。它也让 Windows 当前受支持的候选发现范围（`BootOrder ∪ BootCurrent ∪ BootNext`）能发现/配置新入口。

## Why

- A 不能满足普通启动仍保留菜单。
- B 虽不改 BootOrder，但每天要写 BootNext 和 grubenv 两处状态；Windows 要管理共享 ESP 文件，且 GRUB timeout/marker 消费路径还需额外定制。
- C 将日常一次性选择继续交给标准 BootNext；普通 GRUB 和反向切换的现有流程不变。只在明确的一次性 provision/uninstall 生命周期中处理新入口和 BootOrder。
- 同一 GRUB EFI 文件无论 UEFI description 是什么，都会加载其原配置；标签不会令 GRUB 知道 BootHop 的意图。
- 推荐 UKI 不是因为引入 systemd-boot；UKI 是一个直接由 UEFI 加载的 EFI 镜像，mkinitcpio 支持在 preset 中固定其输出路径。它比单独 GRUB 镜像少一个 GRUB 专用配置/重建路径，且可在 Secure Boot 开启时作为整体签名，但会新增 Arch kernel-preset 集成。

## BootHop changes required

- 新增明确、仅 Linux setup 使用的特权 `ProvisionArchEntry` 操作；不把固件创建隐式塞进现有 `Configure`，更不能放入日常 `Switch`。现有固定 helper、信任边界和最小参数原则保留，不增 daemon/service/executable。它会扩展同一个 helper 的固件写白名单，必须独立复审；不能将日常免认证授权解释为允许 GUI 指定任意变量、路径或启动项。
- Provisioner 必须从本机真实 Arch 配置建立固定 UKI 路径及命令行，不接受 GUI 任意路径、Boot ID、EFI payload 或 canonical identity 作为可信输入。
- 增加 root 保护的 entry ownership 元数据：被分配的 Boot ID、结构身份、受控创建时的完整记录摘要/版本，以及 UKI 路径/构建状态。普通 per-OS target record 仍按 Windows/Linux 分开保存。
- 未来 Windows production implementation 通过 Inspect/Configure/Switch 使用已 provision 且列入 BootOrder 的 Arch 项；`Switch` 仍只接受 `Os::Linux` 意图，并基于受保护目标重新验证身份与 BootNext。Windows 平台生产实现尚未完成。
- 现有核心语义需明确例外：日常 Switch 保持“只写 BootNext”；显式 provision/uninstall 会创建/删除受所有权记录约束的 Boot####，并在首次 setup/uninstall 时更新 BootOrder。

## Linux / GRUB changes required

- 普通 GRUB 配置、默认菜单和 `Boot0000` 不改。
- 在明确 setup 中配置 mkinitcpio 的 UKI preset，输出到固定、固件可读的 ESP 路径；kernel 更新时使用已有 preset/hook 自动重建，不维护版本化 BootHop kernel 副本。
- provision 前验证当前系统确实由已支持的 Arch GRUB 路径启动、ESP/挂载布局和 kernel/preset 可支持 UKI；unsupported/加密或其他配置无法可靠导出 command line 时 fail closed，不猜测。
- Secure Boot：当前主机研究时为关闭。若实现环境检测到 Secure Boot 开启，只有签名及信任链可验证时才允许 provision；不自动关 Secure Boot、不创建密钥、不降低验证策略。
- Windows 不写 Linux 根文件系统，也不写 GRUB environment block。

## UEFI changes required

- 首次 provision：先构建/验证固定 UKI，再读取并保存 BootOrder 原始状态；选未占用 Boot ID；仅创建专用 Boot####；读回并解析核对；把 ID 一次性追加到 BootOrder 末尾；读回确认旧项目和相对顺序不变、新 ID 恰出现一次；最后写 root-protected ownership record。不得使用会隐式置顶/重排的通用“create boot option”路径。
- Boot#### 指向固定 UKI file path 与正确 ESP/GPT device path；不把 Boot ID 本身视为 identity。Description 仅供用户识别。记录及每次 Switch 按既有 canonical identity 与 OptionalData exact 规则验证；同时验证 UKI 本地文件存在/格式。不得据此宣称 kernel 一定能启动。
- 日常 Switch：只读 BootOrder、目标 Boot####、BootNext 与目标文件；仅在现有 conflict/readback/reboot 安全流程要求时写 BootNext。不得触碰 BootOrder 或 Boot####。
- 不变量是“BootHop 从不在日常 Switch 写 BootOrder”，不是“整段安装生命周期 BootOrder 永远不变”。任何固件/外部软件导致列表变化时，仅在重新读取且能保留当前完整顺序的显式 setup/uninstall 中操作；无法可靠判断则停止报告。

## First-time setup flow

1. Linux 侧以用户可见、明确确认的 setup 开始，解释：会生成 Arch 直达 UKI、创建持久 UEFI 项并把它追加到 BootOrder 末尾；普通启动默认项/既有顺序不置换。
2. 只读检测 UEFI/ESP、Arch kernel/initramfs/microcode/root command line、mkinitcpio preset、Secure Boot 和 BootNext。当前 BootNext 存在、配置不支持、未知记录版本或任何状态不确定时停止。
3. 通过受限 helper 构建并验证 UKI；在第一笔 EFI 变量写入前，先原子保存 `Provisioning` 所有权记录（预留 ID、预期 load-option 摘要、operation/version）。随后创建并读回 Boot####、末尾追加 BootOrder 并验证，最后将记录标为 `Ready`。分步写入不是事务；部分成功必须报告 residual，不能盲目删除/回滚或分配另一个 ID。
4. 在 Windows 启动后由用户主动运行 Windows BootHop 的 Inspect/Configure，人工确认 `BootHop Arch` 的 Linux 语义。Linux 侧完成安装不代替 Windows 本地配置。
5. 在取得真实单次 BootNext/reboot 验收授权前，不执行第一次真实 BootHop target 测试。

## Daily Quick Hop flow

Windows 普通 BootHop 启动 → 无主 GUI → helper 从 Windows 受保护记录取得 Arch 目标 → 重新读取 BootOrder 与 live Boot####，验证 canonical identity/OptionalData exact 和本地安装状态 → 读取 BootNext 冲突 → 若 absent，写 `BootNext=BootHop Arch ID` 并立即读回 → 请求正常 reboot。若 BootNext 已是目标则不重复写；指向他项或读取未知则停止。日常不写 grubenv、BootOrder、Boot####、UKI 文件或 GRUB config。

固件先尝试 BootNext；BootHop Arch UKI 直接进入 Arch。固件消费 BootNext 后，下次普通开机回到原 BootOrder 首项 Boot0000，仍呈现既有 GRUB 菜单。

## Failure / recovery behavior

- provision 在 Boot#### 与 BootOrder 间失败时，分别报告 entry 是否存在、BootOrder 是否含该 ID、ownership record 是否已保存；不自动分配第二个 ID，不对未知状态写入或删除。
- 若进程/系统在中间状态退出，root-owned `Provisioning` 记录只用于报告/显式恢复；启动时不自动继续写 EFI、不自动清理。
- live entry 缺失、身份不符、UKI 缺失/格式不支持、Secure Boot 签名不可接受或 BootNext 冲突时，Switch 失败且不 reboot；不追随相似条目，不隐式重建。
- UKI 构建失败不替换已知可用文件；BootOrder 仍保持既有顺序。原 `Boot0000` + GRUB 仍是人工恢复路径。
- 明确 setup 才可重新 provision；identity 失配先要求用户确认并重新建立所有权，不覆盖未知 Boot####。
- uninstall 是显式且需授权的逆序清理：确认 BootNext 不指向该项、Boot#### 与 ownership 精确匹配；从当前 BootOrder 中只移除该 ID并保持其他项原相对顺序，读回后再删除 Boot#### 与 BootHop UKI/所有权记录。发现并发/外部变化、无法证明不会覆盖时停止并留待管理员处理；不做盲目恢复。UEFI 没有已核实的 BootOrder compare-and-swap，因此实现仍须承认跨进程固件变量竞态，不能声称 read-modify-write 具备事务安全。

## Update compatibility

- mkinitcpio preset 使用稳定 UKI 路径，kernel/initramfs/microcode 更新重新生成同一文件；Boot#### path 不随 kernel 版本变化，Windows 目标 canonical identity 不需因 kernel 升级而重配。
- 更新失败时保留上一份可用 UKI，错误可见；不得留下“更新成功但 UKI 缺失/截断”。需测试原子替换策略与磁盘空间不足。
- root UUID、内核参数、initramfs 配置、kernel flavor 或 ESP 布局变化需重新确认 preset/UKI；不能声称 BootHop identity 验证证明镜像语义正确。
- 固件升级可重排或移除 Boot####/BootOrder；Inspect/Switch 重新读取并 fail closed。不得无提示自动复原。
- Secure Boot 开启时更新后的 UKI 必须继续由固件信任链接受；密钥管理不属于本提案。

## Acceptance plan

1. Fake tests：Boot#### ID 竞态/占用、记录写入顺序、BootOrder append 保序、短写/读回失败、每个部分成功状态、同目标/冲突 BootNext、并发修改、unsupported config fail closed、UKI 更新失败保留旧文件、uninstall 不删除他项。
2. Linux 虚拟 UEFI：使用独立测试磁盘与固件变量，确认安装前后原 `BootOrder` 前缀和相对顺序、BootHop 只追加一次，BootNext 直启 Arch UKI 并被消费，下一次普通启动进入原 GRUB 菜单；另测 UKI 更新、签名/拒绝及故障恢复。
3. 实机：仅在单独明确授权后测试；分别记录 provision 前后 BootOrder、BootNext 写请求/API结果/readback、reboot 接受、BootCurrent/BootNext 后态、人工确认实际进入 Arch，以及下一次普通 GRUB 菜单仍在。任何其他 BootOrder/Boot#### 变化即失败。

此计划不是 dry-run；软件测试不得读取宿主 UEFI 或执行真实启动。

## Rollback plan

在正式启用前保留当前原始启动项和 BootOrder 记录，并确认可访问固件启动选择/现有 GRUB 恢复路径。失败时不清理未知变量、不覆盖外部更新。只有所有权/identity 精确匹配且当前 BootNext 未指向该入口时才显式卸载：从 BootOrder 删除专用 ID、验证顺序保留，再删除对应 Boot#### 与 UKI。任何一步状态未知则停止并报告人工恢复所需的准确对象；不声称 BootHop 可保证 firmware NVRAM 回滚事务。

## 研究依据与未决审批

- UEFI 2.11 定义 BootNext 优先尝试一次、移交前删除、之后恢复普通 BootOrder；其自动维护说明没有保证长期保留未被 BootOrder/BootNext 引用的 Boot####。来源：[UEFI Boot Manager §3](https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html)。因此 UEFI 可理解“BootNext 指向一个现存 Boot####”，但不能据此保证精确不变的 BootOrder 与 orphan entry 长期共存。
- GRUB `next_entry` 是另一个 one-shot 状态，environment block 有文件系统/写入限制；`saved_entry` 是持久默认。来源：[GRUB next_entry](https://www.gnu.org/software/grub/manual/grub/html_node/next_005fentry.html)、[GRUB environment block](https://www.gnu.org/software/grub/manual/grub/html_node/Environment-block.html)、[saved_entry](https://www.gnu.org/software/grub/manual/grub/html_node/saved_005fentry.html)。
- Linux EFI stub 可作为 EFI 应用运行，`initrd=` 路径相对 ESP 根且必须为 EFI 路径；mkinitcpio 官方手册支持在 preset 中配置固定 `_uki` 输出路径。来源：[Linux EFI Boot Stub](https://docs.kernel.org/admin-guide/efi-stub.html)、[Arch mkinitcpio(8)](https://man.archlinux.org/man/mkinitcpio.8)、[systemd-stub(7)](https://man.archlinux.org/man/systemd-stub.7.en)。
- 与现有批准设计的差异：新增 UEFI entry 创建/删除、一次性 BootOrder append/removal、Arch UKI preset 与 ownership state；不符合“BootHop 永不创建/修改 Boot####、永不修改 BootOrder”的现行规则。实现前必须由用户明确批准这个例外，或要求研究替代方案。当前没有获准的 Windows↔Arch 专用 entry 生产实现。

### Review checklist

- 保留普通 GRUB 菜单：是，Boot0000、普通配置和原相对顺序不动。
- Windows → Arch 绕过人工选择：目标是直接运行 UKI；必须 UEFI 虚拟机和获批实机验收，不能仅凭变量读回声称成功。
- 日常只写 BootNext：是。
- 是否新增 Boot####：是，显式 setup 创建一个固定专用项；不在 Switch 中创建/修复。
- BootOrder：首次 setup 追加一次，uninstall 显式移除；日常切换不写。严格“永不改变 BootOrder”与此可移植设计不兼容。
- 是否改 Rust：是，新增受限 provision 请求、Linux UEFI Boot####/BootOrder adapter、ownership state 与测试；日常共享 Switch 状态机应尽量不变。未来 Windows production line 可沿用既有候选发现/Configure/Switch 契约，但尚未实现。
- 最大风险：固件变量创建/BootOrder 更新不是事务；安全 BootNext 行为和真实链路需分阶段验收，不能用模拟代替。
- Ready for implementation：**NO**，等待用户审阅本提案，尤其确认是否接受首次 setup/uninstall 对 BootOrder 的一次性修改，以及 UKI/update-hook 这一 Arch 集成范围。
