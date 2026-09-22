# BootHop Windows → Arch Handoff

Date: 2026-09-23  
Repository: `https://github.com/crazy486/BootHop.git`  
Development branch: `boothop-simple`  
Verified source baseline before this documentation-only handoff: `ac917a4380c43f694a5817b6f705feaa2a60fd0d`  
Quick Hop implementation commit: `f5c6d4fab850ad907fcdef3890a9302599ac7d9d`  
GitHub Actions run `35755449766` for `ac917a4`: Linux PASS, Windows PASS.

The commit containing this file is a documentation-only descendant of the verified source baseline. A receiving agent must use the exact `origin/boothop-simple` tip advertised with the final handoff message and verify it with `git rev-parse HEAD`; it must not reset back to `ac917a4` merely because that is the code baseline named above.

## 1. 当前项目目标

BootHop 是一个“配置一次，以后双击应用就直接切换到另一个操作系统并正常重启”的小工具，不是双系统管理器。已配置时，普通启动不显示主 GUI，而是在窗口创建前发送恰好一次固定对侧 OS 的 `Switch`。未配置、缓存不可用、显式设置模式或任何失败/不确定结果才显示现有配置/错误界面，并且不会自动重试。内部仍保留受保护记录、live firmware identity、BootNext 冲突、写后读回及正常重启的全部安全检查；零交互不等于绕过验证。

## 2. 当前 Git 状态

- repo：`crazy486/BootHop`
- branch：`boothop-simple`
- Windows 交接准备时 local HEAD / `origin/boothop-simple`：`ac917a4380c43f694a5817b6f705feaa2a60fd0d`
- push：local 与 origin 一致；本 handoff 将作为普通后继提交再次 push。
- tracked worktree：clean。
- Windows 本机原有未跟踪目录：`trusted-target-task1/`、`trusted-target-task1-round2/`。它们没有被修改、清理、提交或 push，也不应期待出现在新的 Arch clone 中。
- `.superpowers/`、`target/`、`.worktrees/` 由 `.gitignore` 排除；Linux/Windows 原始 firmware evidence 不随 GitHub clone 迁移是设计行为，不是数据丢失。
- 关键提交：
  - `ac917a4` — `docs: record Quick Hop completion`
  - `f5c6d4f` — `style(gui): format Quick Hop changes`
  - `b28aaa5` — `feat(gui): add zero-ui quick hop startup path`
  - `8effc7d` — `docs: define Quick Hop product path`
  - `4fc0769` — 保留的 `boothop-sdd` 历史基线与 Windows SAC blocker 记录

## 3. Quick Hop 已实现行为

- configured 普通启动：读取普通用户 cache 作为“可能已配置”的路由提示；OS 匹配时同步发送一次 `Request::Switch { os: Windows }`。只有 helper 返回经过 controller 验证的 `TargetValidated → BootNextVerified → RebootAccepted` 报告时，进程在构造 Slint `AppWindow` 前退出。
- unconfigured：cache 不存在时不自动启动 helper，不自动 Switch，进入现有最小配置界面。
- cache 不可读、格式错误或 OS 不匹配：fail closed，显示现有错误/设置界面，不猜测目标。
- settings：`/usr/bin/boothop-gui --setup` 与 `--settings` 都强制进入配置界面，不自动 Switch。未知或冲突参数也安全落到可见设置界面。
- failure：BeforeSend、helper/polkit、validation、firmware、read-back、reboot rejected 或 UnknownAfterSend 都不会自动重试；错误界面保留有界诊断。Unknown 可能意味着 BootNext 或重启请求已经生效，严禁重复双击。
- cache 不是信任源：真正的 Boot ID、OS 和 canonical identity 来自 root 保护的 record，并在 helper/core 内对 live firmware 重新验证。

## 4. 当前架构最小地图

```text
/usr/share/applications/org.boothop.desktop
  Exec=/usr/bin/boothop-gui
    → crates/gui/src/main.rs
    → crates/gui/src/controller.rs
    → crates/gui/src/helper_client.rs
    → crates/gui/src/helper_client/linux.rs
    → /usr/bin/pkexec --disable-internal-agent /usr/lib/boothop/boothop-helper
    → crates/helper/src/main.rs
    → crates/helper/src/dispatch.rs + crates/helper/src/lock.rs
    → crates/core/src/flow.rs Request::Switch
    → crates/platform/src/linux.rs
      → crates/platform/src/linux/firmware.rs
         /sys/firmware/efi/efivars/BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c
      → crates/platform/src/linux/reboot.rs
         org.freedesktop.login1.Manager.RebootWithFlags(uint64 1)
```

关键控制流：core 先加载受保护 record、检查环境、枚举并解析 BootOrder/BootCurrent/Boot####、重新验证已保存目标 identity；随后读取 BootNext。BootNext 已指向不同目标时停止；不存在时只写一次 6 字节 efivarfs 内容（属性 7 + little-endian `u16` Boot ID）；然后独立读回。只有读回等于目标才调用 logind 正常重启。Linux adapter 没有已批准的安全 CAS/restore 证明，因此不会盲目清除或恢复 BootNext。

## 5. Linux 端关键路径和文件

安装后路径：

- GUI / daily launcher：`/usr/bin/boothop-gui`
- privileged helper：`/usr/lib/boothop/boothop-helper`
- desktop entry：`/usr/share/applications/org.boothop.desktop`
- polkit policy：`/usr/share/polkit-1/actions/org.boothop.helper.policy`
- protected state directory：`/var/lib/boothop`，要求 `root:root`、mode `0700`
- protected record：`/var/lib/boothop/targets.json`，由 helper 创建并要求 `root:root`、mode `0600`
- persistent operation lock：`/var/lib/boothop/operation.lock`，要求 `root:root`、mode `0600`
- ordinary-user routing/display cache：`${XDG_STATE_HOME:-$HOME/.local/state}/boothop/cache-v1.json`；不可信，但普通自动 Quick Hop 需要一个 OS 匹配的有效 cache hint
- efivarfs：`/sys/firmware/efi/efivars`
- Global Variable GUID：`8be4df61-93ca-11d2-aa0d-00e098032b8c`

仓库路径：

- Quick Hop amendment：`docs/superpowers/specs/2026-09-23-quick-hop-amendment.md`
- Quick Hop plan：`docs/superpowers/plans/2026-09-23-quick-hop.md`
- completion handoff：`docs/superpowers/handoffs/2026-09-23-quick-hop-complete.md`
- 原始仍有效安全约束：`docs/superpowers/specs/2026-09-08-boothop-design.md`
- Linux contracts：`docs/research/shared-linux-prerequisites.md`、`docs/research/platform-contracts.md`
- firmware/reboot run sheet：`docs/acceptance/firmware.md`
- GUI/release gaps：`docs/acceptance/gui.md`、`docs/acceptance/release.md`
- Linux packaging：`packaging/linux/`
- CI：`.github/workflows/test.yml`

## 6. Arch 克隆与恢复命令

全新 clone：

```bash
git clone https://github.com/crazy486/BootHop.git
cd BootHop
git fetch origin --tags --prune
git switch --track origin/boothop-simple
git status --short --branch
git rev-parse HEAD
git rev-parse origin/boothop-simple
```

GitHub 默认分支仍是 `boothop-sdd`，所以普通 clone 后必须显式跟踪 `origin/boothop-simple`。若本地分支已存在，使用：

```bash
git switch boothop-simple
git pull --ff-only origin boothop-simple
```

预期 `HEAD` 必须等于最终交接消息给出的 exact SHA，且等于 `origin/boothop-simple`。任何不一致、tracked dirty 状态或意外提交都应停止；不要 reset/force-push 来掩盖差异。

## 7. 构建 / 安装 / 测试方法

### 7.1 普通 fake / CI 检查

使用仓库固定 Rust `1.98.1` 和 lockfile。Arch 需要可工作的 Rustup/Cargo、`rustfmt`、`clippy`、基础编译工具、`pkgconf` 与 fontconfig 开发环境；额外 GUI 运行库以实际 Arch 机器和 `docs/research/support-matrix.md` 核对。

```bash
cargo test --workspace --locked
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
packaging/linux/check-isolation.sh
packaging/linux/tests/isolation_checker_fake.sh
packaging/linux/tests/installer_fake.sh
packaging/linux/package-smoke.sh
```

这些命令是 fake/static/CI，只能证明软件与包布局；它们不得调用已安装 helper、pkexec、真实 efivarfs、system D-Bus reboot 或 GUI event loop，也不等于真实验收。

### 7.2 development package build（不安装）

```bash
mkdir -p "$PWD/out"
packaging/linux/build-package.sh "$PWD/out"
sha256sum "$PWD"/out/boothop-linux-*.tar.gz
```

这只在临时 staging 中制作 development tarball。它不安装、不创建 `targets.json`、不访问 firmware、不重启。

### 7.3 exact-HEAD release build 与真实安装

安装会修改 `/usr`、`/var/lib/boothop` 和 polkit action，必须在 Arch 主机上明确作为 acceptance provisioning 记录，不能伪装成 fake test：

```bash
cargo build --workspace --release --locked
sudo packaging/linux/install.sh check-destdir --destdir / --production --live-root
sudo packaging/linux/install.sh install \
  --destdir / \
  --payload "$PWD/target/release" \
  --production \
  --live-root
sudo packaging/linux/install.sh inspect --destdir / --production --live-root
```

随后验证 exact artifacts 和布局：

```bash
sha256sum target/release/boothop-gui target/release/boothop-helper
sudo sha256sum /usr/bin/boothop-gui /usr/lib/boothop/boothop-helper
sudo stat -c '%U:%G %a %F %n' \
  /usr/bin/boothop-gui \
  /usr/lib/boothop/boothop-helper \
  /usr/share/applications/org.boothop.desktop \
  /usr/share/polkit-1/actions/org.boothop.helper.policy \
  /var/lib/boothop \
  /var/lib/boothop/operation.lock
```

安装不会伪造或预创建 `targets.json`。若 protected record 为 Absent，则用 `/usr/bin/boothop-gui --setup` 做首次真实 Inspect → 人工选择确切 Windows Boot Manager → 确认 OS=Windows → Configure。Configure 写受保护 record 和用户 cache，但不写 BootNext、不重启。不要手写 `targets.json` 或 cache。

## 8. 已知风险和 blocker

- Windows Smart App Control / Win32 4551 会阻止当前 Windows 机器上的未签名新 helper/build script。这是 Windows 签名/主机策略 blocker，不是 Linux core/Switch defect，也不阻止 Arch 上的 Linux → Windows 验收。
- Linux 当前 policy 的 `allow_active` 仍是 `auth_admin`；第一次 Quick Hop 允许出现一次 polkit 管理员认证。不要在本次验收前把它改为 `allow_active=yes`，因为同一 action 也覆盖 Configure。
- Linux 日常免密码尚未实现；它是闭环成功后的下一独立任务。
- Windows 日常免 UAC 尚未实现；可靠方案很可能需要安装期受保护 broker/service 或等价集成，本轮不设计。
- success path 不持久化一份公开 stage log。`RebootAccepted` 前的 `TargetValidated` 与 `BootNextVerified` 由已审查控制流强制，但实机报告应区分“生产控制流 attestation”与“独立 raw firmware observation”，不得把不可见 stage 伪造成独立捕获。
- BootNext 读回只证明值被设置，不证明 firmware 会服从它；只有用户在 reboot 后真实看到 Windows 才能记录“实际进入 Windows：PASS”。

## 9. Arch 下一步唯一主任务

唯一主任务是：**完成第一次真实 Linux → Windows Quick Hop acceptance。**

不要重新设计产品、不要先做 Linux 免密码、不要删除 GUI/controller、不要恢复“每次打开 GUI 再点 Switch”的旧方向。目标闭环是：Arch 上单次双击 BootHop；必要时接受一次 polkit；成功路径不出现正常主窗口；helper 重新验证 Windows 目标、设置并读回 BootNext、通过 logind 正常 reboot；用户真实观察进入 Windows。

## 10. 真实验收前 checklist

### 10.1 Git 与构建身份

- [ ] `git fetch origin --tags --prune`
- [ ] current branch=`boothop-simple`
- [ ] `git status --short --branch` 无 tracked 修改
- [ ] `git rev-parse HEAD` 等于最终 handoff exact SHA
- [ ] `git rev-parse origin/boothop-simple` 与 local HEAD 相同
- [ ] installed GUI/helper SHA-256 与该 HEAD 的 release build 相同

### 10.2 环境能力

- [ ] `cat /etc/os-release` 确认 Arch Linux
- [ ] `uname -a`、`hostnamectl`、当前日期时间已记录
- [ ] `test -d /sys/firmware/efi/efivars` 成功，确认不是 legacy BIOS
- [ ] `findmnt -no FSTYPE,OPTIONS /sys/firmware/efi/efivars` 显示 `efivarfs` 且非只读
- [ ] `systemctl --version` 的 systemd >=255
- [ ] polkit backend >=124，当前图形 session 有可见、正常工作的 authentication agent
- [ ] `systemd-logind`、polkit 和 system D-Bus 正常
- [ ] logind introspection 中存在 `org.freedesktop.login1.Manager.RebootWithFlags(t)`
- [ ] 用户已保存工作，并理解成功调用将立即正常 reboot

### 10.3 安装与配置状态

- [ ] `/usr/bin/boothop-gui`、`/usr/lib/boothop/boothop-helper` 与 package metadata 均来自 exact HEAD
- [ ] `/var/lib/boothop` 为 `root:root 0700`
- [ ] `/var/lib/boothop/operation.lock` 为 `root:root 0600`
- [ ] `/var/lib/boothop/targets.json` 存在且 root 可读；不要把全文复制到 tracked log
- [ ] `${XDG_STATE_HOME:-$HOME/.local/state}/boothop/cache-v1.json` 对当前桌面用户存在；cache 只作 routing hint
- [ ] 已保存 target OS=Windows，目标 Boot ID 已记录
- [ ] Windows Boot Manager 的 live Boot#### 仍存在；不要根据名称自动改绑

### 10.4 private evidence

在仓库内使用被 Git 忽略的路径，先验证 ignore：

```bash
RUN_ID="linux-quick-hop-$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_ROOT="$PWD/.superpowers/sdd/2026-09-23-quick-hop/private/linux-real/$RUN_ID"
umask 077
mkdir -p "$EVIDENCE_ROOT"
git check-ignore -v "$EVIDENCE_ROOT"
```

若 `git check-ignore` 没有证明该路径被忽略，停止，不要写 raw evidence。记录环境、Git SHA、artifact hashes、安装 stat、目标 OS/Boot ID。若系统已有 `efibootmgr`，下面是不修改 firmware 的只读捕获：

```bash
sudo efibootmgr -v | tee "$EVIDENCE_ROOT/efibootmgr-before.txt"
```

不得给 `efibootmgr` 使用 `-o`、`-n`、`-c`、`-b ... -B` 等写入参数。若不用 `efibootmgr`，只读保存固定 control variables；文件前 4 字节是 efivar attributes，后续才是 payload：

```bash
EFI_DIR=/sys/firmware/efi/efivars
EFI_GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c
for name in BootOrder BootCurrent BootNext; do
  path="$EFI_DIR/$name-$EFI_GUID"
  if sudo test -e "$path"; then
    printf '%s present: ' "$name" | tee -a "$EVIDENCE_ROOT/control-vars-before.txt"
    sudo od -An -tx1 -v "$path" | tee -a "$EVIDENCE_ROOT/control-vars-before.txt"
  else
    printf '%s absent\n' "$name" | tee -a "$EVIDENCE_ROOT/control-vars-before.txt"
  fi
done
```

- [ ] before `BootOrder` recorded
- [ ] before `BootCurrent` recorded
- [ ] before `BootNext` recorded as exact value or confirmed absent
- [ ] target Boot#### ID, length, attributes and hash recorded privately
- [ ] no raw Boot#### payload or full device path will be committed
- [ ] no other BootHop/helper process is running
- [ ] no conflicting BootNext points to another target; if it does, stop and do not overwrite

### 10.5 single activation

- [ ] Close the settings UI after configuration; do not press its legacy visible Switch button for this Quick Hop acceptance.
- [ ] From the desktop application launcher, activate **BootHop** exactly once (`org.boothop.desktop` → `/usr/bin/boothop-gui`).
- [ ] Do not double-click again while polkit/helper is pending.
- [ ] Accept the single expected polkit prompt if the host policy requests it.
- [ ] If any normal main window appears before reboot, capture it and stop; do not click Switch again.

## 11. 真实验收成功标准

逐项记录 PASS / FAIL / NOT OBSERVED，并写清证据类型：

1. [ ] BootHop exact installed launcher started once.
2. [ ] ordinary-user cache correctly routed to configured Windows target; no setup flow was required.
3. [ ] normal main GUI did not appear on accepted success path.
4. [ ] operator initiated exactly one activation; no concurrent/repeated helper request occurred.
5. [ ] polkit authorization and fixed helper launch completed.
6. [ ] production control flow accepted protected/live target identity (`TargetValidated`).
7. [ ] production control flow wrote or retained the target BootNext according to conflict rules.
8. [ ] production control flow independently read back the target (`BootNextVerified`).
9. [ ] logind returned an accepted reply to `RebootWithFlags(1)` (`RebootAccepted`).
10. [ ] user manually observed the machine actually enter Windows. Only this observation permits `实际进入 Windows：PASS`.
11. [ ] post-boot read-only evidence confirms permanent BootOrder is unchanged from the Arch pre-run value.
12. [ ] post-boot BootNext state is recorded separately as consumed/absent/value/unavailable; do not infer semantics from an undocumented error.

Items 6–9 may be control-flow attestations unless independent evidence exists; label them honestly. On Windows, post-boot BootOrder/BootNext observation is a separate read-only operation and must not silently invoke mutation. If a Windows-native read requires elevation/privilege or the existing Windows1W collector, use its own explicit read-only scope and preserve its known BootNext limitation; do not substitute BCD changes or firmware writes.

## 12. 禁止事项

- 不修改 BootOrder 或任何 Boot####。
- 不创建、删除或“修复” EFI entry。
- 不修改 BCD。
- 不直接手写 efivarfs；BootNext 只允许由 production Switch 的既有 typed path 写入。
- 不关闭/削弱 polkit、Smart App Control、Defender、UAC 或其他安全策略。
- 不用 `NOPASSWD: ALL`、setuid 或宽泛授权绕过认证。
- 不在未知结果、timeout、断连或已有冲突 BootNext 时重复 Switch。
- 不盲目清除 BootNext；只有现有 ownership/rollback contract 能决定后续状态。
- 不把 cargo tests、package build、fake CI 或 BootNext read-back冒充“实际进入 Windows”。
- 不在首次实机闭环前重构产品、增加 daemon/service 或恢复旧 GUI-first 产品方向。
- 不提交 raw firmware payload、完整 machine-specific device path、私有 screenshot 或 protected record。

## 13. 如果成功，下一任务

成功闭合 Linux → Windows Quick Hop 后，下一独立任务是：**在不扩大架构的前提下，最小化 Linux 日常 Switch 的密码输入。** 优先复用 one-shot helper 与 install-time/polkit 的极窄 operation-specific 权限；不得直接把当前同时覆盖 Inspect/Configure/Switch 的 action 改为 blanket `allow_active=yes`，不得默认增加 daemon/service，不得使用 `NOPASSWD: ALL`。若严格区分 Configure 与 Switch 需要拆 action 或增加 broker，先报告代码量、安装面和安全代价，等待产品决策。

## 14. 如果失败

立即停止在最近安全状态，不重试。把证据写入上述 ignored private run 目录，并创建一份不含 raw payload/完整路径的 tracked handoff。至少记录：

- date/time、hostname、OS/kernel、desktop/session、systemd/polkit 版本
- branch、exact HEAD、installed GUI/helper SHA-256
- protected record/cache 的存在状态、目标 OS 与 Boot ID（不提交完整 record）
- before BootOrder、BootCurrent、BootNext 语义摘要
- failure phase：BeforeSend / helper launch / authentication / validation / firmware read / BootNext conflict / write / read-back / reboot request / actual boot / post-boot observation
- raw errno、pkexec exit code、bounded BootHop diagnostic、已确认 stages
- BootNext 是否可能残留、是否由本次操作写入、为何不能安全 rollback
- BootOrder 是否保持不变
- 是否真实 reboot、实际到达哪个 OS
- worktree、commit/push、CI 状态与下一条精确恢复命令

若失败发生在请求完整发送前，保持机器原状并诊断 fixed helper/polkit/install boundary。若请求发送后结果 Unknown，假定 BootNext 或 reboot 可能已生效；不要再次启动 BootHop。若 BootNext 写入后 read-back/reboot 失败，严格遵守现有 ownership/rollback 报告，不自行清理。若机器进入错误 OS 或 BootOrder 改变，标记 acceptance FAIL，保留证据并停止所有自动修复。

本 Windows 交接任务没有调用 Linux helper、firmware API、BootNext、BootOrder、Boot####、BCD、Switch、reboot 或 shutdown。
