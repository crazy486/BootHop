# 共享与Linux前置契约：1S.parse / 1S / 1L

日期：2026-09-10。Linux-first修订独立审查Approved，用户条件授权已生效。1S.parse/1S独立审查APPROVED（66eaf9f），1L修复后独立Spec/Quality审查APPROVED（600aa4d）。这是前置文档契约的审查证据；代码任务及测试审查进度以manifest和controller ledger为准，不把契约批准当实现或真实验收完成。Task1总体仍BLOCKED，1W仍缺Windows原生只读实证。本轮仅状态记账，不读取固件、不提权、不执行写入、重启或安装。

## 1. 1S.parse：有界UEFI解析验证表（APPROVED，66eaf9f）

输入 `parse_load_option(&[u8]) -> Result<LoadOption, Error>` **只接收变量payload**，不含Linux的4字节变量属性前缀。最大payload沿用平台契约1 MiB（1,048,576字节），超限ResourceLimit，不截断。所有长度加法先checked，所有读取先slice边界检查；不依赖自然对齐，不用unchecked索引或指针转换。UTF-16均逐个小端u16读取；只有编码有效才用于显示，禁止以替换字符修复非法编码后继续。

`LoadOption`保留 `attributes: u32`、`description_utf16: Vec<u16>`（不含终止NUL）、`file_path_list_length: u16`、`file_paths: Vec<DevicePath>`、`optional_data: Vec<u8>`。`DevicePath`保留有序实例与节点；节点保留type/subtype/length及原payload，可额外解码已知节点。解析时不分类OS、不认为ACTIVE或变量attributes已有效、不计算可信identity；原始OptionalData仅为helper内存数据，不进入可信记录/GUI缓存/普通日志。

`parse_device_path(&[u8]) -> Result<DevicePath, Error>`消费恰好一个以EndEntire结束的完整路径（可含EndInstance）。load-option解析器在FilePathListLength限定切片内，以有界节点长度找到每个EndEntire并逐个解析，保留多个完整路径元素，不把第二元素误当OptionalData。未知节点只保留有界原文供诊断，**可解析不代表identity支持**；Task3另行拒绝未知前缀、多实例/多元素/多FilePath。

以下名称为synthetic测试要求；实际实施与通过结果见manifest和controller ledger，不由本文重复判定，也不把后续identity测试提前标为完成。正反例按此契约构造，无需公开私有样本，也不冒充自然更新。

| 检查 | 精确结果/边界 | 正例测试 | 反例测试 |
|---|---|---|---|
| payload上限/固定头 | 长度<=1 MiB且>=6；[0..4]为u32 attributes，[4..6]为u16路径列表字节数 | `parse_header_little_endian_unaligned` | `rejects_truncated_header`、`parse_payload_over_limit` |
| description终止 | 从偏移6按2字节扫描，首个u16零终止；终止必须完整位于payload内；空描述可解析 | `parse_empty_and_unicode_description` | `parse_description_missing_nul`、`parse_description_half_code_unit` |
| description编码 | 终止前码元按UTF-16验证；代理项必须正确成对，合法非BMP保留原码元 | `parse_description_surrogate_pair` | `parse_description_unpaired_surrogate` |
| OptionalData起点 | checked(6 + description含NUL字节数 + FilePathListLength)，不得超payload；起点后全部剩余字节原样保留 | `parse_empty_binary_odd_length_optional` | `path_list_length_overflow_rejected` |
| 文件路径列表 | 非零长度必须被完整路径元素恰好消费；零长度可保留空列表供目标验证拒绝，不宣称可启动 | `parse_multiple_complete_path_elements`、`parse_zero_path_list` | `parse_path_list_trailing_partial_header` |
| 节点通用边界 | 4字节头，length为u16 LE、>=4；checked前进且不越所属切片；保留type/subtype/顺序 | `parse_unknown_node_preserved` | `truncated_node_rejected`、`parse_zero_or_short_node_length` |
| 终止节点 | type=0x7f；EndInstance subtype=0x01、EndEntire=0xff，二者length必须4；EndInstance后仍须有后续实例并最终EndEntire；单path API不接受EndEntire后的额外字节 | `parse_multiple_instances`、`parse_end_entire` | `parse_bad_end_length`、`parse_missing_end_entire`、`parse_end_instance_without_final_path` |
| 已知HD节点 | type=4/subtype=1必须length42后才解码全部字段；MBR/GPT值只是数据，支持检查另做 | `parse_hd_fields_little_endian` | `parse_hd_wrong_length` |
| 已知FilePath节点 | type=4/subtype=4；body至少一个u16终止符、偶数字节，末尾恰为首个NUL；终止前UTF-16有效，不接受嵌入NUL后的尾字节 | `parse_filepath_unicode`、`parse_empty_filepath` | `parse_filepath_odd_length`、`parse_filepath_embedded_nul`、`invalid_utf16_path_rejected` |
| OptionalData不解码 | 包括零、奇数字节、非UTF-16和未知魔数均原样保留；无尾部/字符串清理 | `parse_optional_all_bytes_preserved` | `parse_optional_not_confused_with_second_path`（断言边界，不因其二进制内容拒绝） |
| 错误不产出目标 | 头/description/列表边界错误→MalformedLoadOption；节点/路径错误→MalformedDevicePath；超限→ResourceLimit；不得返回部分成功LoadOption | `parse_complete_option_only` | `parse_error_has_no_partial_target` |

类型0x7f的未知终止subtype不能当通用未知节点越过终止判定：返回MalformedDevicePath。End-only/空实例即便保留为可解析形状，也不会通过§2的三节点单实例目标规则。以上结构拒绝是BootHop解析契约，不声称UEFI禁止全部未支持输入。

依据：[UEFI 2.11 §3.1.3](https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html)（2026-09-10核对：packed头、含NUL description、路径数组及OptionalData剩余字节）、[UEFI 2.10 §10.3](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html)（沿用2026-09-08已核对的节点定义；本轮2.10/2.11路径网页重开失败，不冒称新全文核对）。编码严格拒绝、资源上限及目标支持范围是BootHop保守策略。现有私有2项支持HD+FilePath+EndEntire及0/136字节边界观测；正反变体仍须实施，不能由两次相同读取推出稳定性或Windows API已验证。

## 2. 1S：保守目标与精确身份（APPROVED，66eaf9f）

本节依据用户已指定范围收敛，不扩大规范化：恰好一个FilePathList元素、一个实例、三个节点，顺序为HD(GPT/GUID)+单绝对FilePath+EndEntire。不接受硬件/ACPI/消息/vendor前缀、网络/USB、MBR/无签名、多实例、多路径元素、多FilePath节点、仅设备无明确文件路径或仅FilePath默认回退。未知节点即使§1可解析，也由目标验证返回UnsupportedFormat；不把未知节点哈希后当已支持。UEFI允许更广的路径，并不意味着本产品支持。

HD要求type4/subtype1/length42、MBRType=2、SignatureType=2、分区号非零、16字节分区签名非全零、分区大小非零，start+size checked无u64溢出。分区号、起始LBA、大小与原UEFI布局的16字节UniquePartitionGuid全部精确比较；不擅自忽略移动/扩容，不进行磁盘GPT读取或声称签名在实际磁盘上唯一。若发现多个条目具有相同canonical identity，inspect标记歧义并要求选择原编号；不把条目重复当磁盘克隆检测，也不自动跟随另一个编号。

FilePath保留终止前UTF-16码元，要求首码元为反斜杠、路径不为空/仅根目录、没有正斜杠、连续分隔符、末尾分隔符、空组件、`.`或`..`组件。字符编码与NUL边界按§1。拒绝这些歧义形状而不是修复；不做大小写折叠、NFC、替换分隔符、路径拼接、文件系统访问或二进制验证。末尾唯一NUL作为固定结构字段验证，路径码元精确比较。

Description仅供显示：合法UTF-16改名不影响identity；空描述允许，显示层转义控制字符，不据名称分类。load-option attributes每次仅允许0x00000001或0x00000009（ACTIVE，HIDDEN可选，CATEGORY_BOOT=0），其他位/未激活均UnsupportedFormat；HIDDEN只影响显示而不改变identity。变量attributes独立要求Boot####/BootOrder/BootNext恰为7，BootCurrent恰为6；未知认证/附加位拒绝。两类attributes不进入identity，但每次inspect/configure/switch都重新验证；权限/读取错误不能被人工OS确认绕过。

所有OptionalData（含空）严格 `OpaqueExactV1 { algorithm: Sha256, byte_length: u64, digest: [u8; 32] }`，源为同一完整解析buffer的全部余字节。成熟库SHA-256完整摘要，不裁剪/NUL清理/重编码/提取子集。any identity差异→IdentityMismatch，停止switch且无WriteNext/Reboot/SaveRecord；原编号不存在也停止，不搜索替代编号。用户主动重新选择确认OS、正常授权configure才建立新基线。全部结构有效仍不能证明最终OS或启动链安全；相同路径二进制/BCD变化、外部检查后变化与SHA-256抗碰撞假设仍是边界。

自动Known启用表为空：当前所有受支持候选均NeedsConfirmation，包含名称看似Windows、GRUB或唯一候选。用户确认Windows/Linux用于configure保存os，不放宽有效性。per-OS只保存对侧目标。未来增加Known或容忍变化需另有依据/审查；自然更新配对只约束未来宽松策略。

### 2.1 字面持久化字段契约

仍为record envelope版本1：根对象只有 `version` 和 `target`；target只有 `os`（字符串Windows或Linux）、`boot_id`（JSON整数u16）和 `identity`。以下路径是**字面字段名/类型规则**，不是实际样本；不提供包含私有值的示例。u64按JSON十进制整数保留精度，禁止浮点中转；Rust直接serde，不经GUI/JavaScript重建可信记录。

| 对象/字段 | 精确类型/值 |
|---|---|
| `identity.kind` / `identity.version` | 字符串`CanonicalIdentity` / 整数1 |
| `identity.file_path_list_length` | u16；等于下列三个节点length之和，不含description或OptionalData |
| `identity.nodes` | 长度恰为3的有序数组，以下分别是索引0/1/2 |
| `nodes[0].kind/type/subtype/length` | `HardDrive` / 4 / 1 / 42 |
| `nodes[0].partition_number` | 非零u32 |
| `nodes[0].partition_start_lba` / `partition_size_lba` | u64 / 非零u64，checked和有效 |
| `nodes[0].partition_signature_uefi_bytes` | 16个u8的JSON数组，原UEFI字节布局，非全零；不转文本GUID或改端序 |
| `nodes[0].mbr_type` / `signature_type` | 2 / 2 |
| `nodes[1].kind/type/subtype` | `FilePath` / 4 / 4 |
| `nodes[1].path_utf16` | 终止前的u16整数数组，编码/绝对路径规则如上，保持原码元 |
| `nodes[1].terminator` / `length` | 0 / u16，必须等于4+2×(path_utf16长度+1) |
| `nodes[2].kind/type/subtype/length` | `EndEntire` / 127 / 255 / 4 |
| `identity.optional_data.kind/version/algorithm` | `OpaqueExact` / 1 / `Sha256`，逻辑对应OpaqueExactV1 |
| `identity.optional_data.byte_length` | u64，<=payload上限；空为0 |
| `identity.optional_data.digest` | 恰64个小写十六进制字符，对应完整32字节SHA-256；空数据必须为空串标准摘要 |

字段全必需、对象不接受未知或重复字段，整数不得为负数/小数/越界；根version先有界解析，未知u64版本→UnsupportedRecordVersion，不要求理解新payload。已支持根版本内，未知identity或optional_data kind/version/algorithm→UnsupportedIdentityComponent；缺字段、类型不对、摘要编码/长度不对、节点数组/常量/派生长度不一致→CorruptRecord。两个unsupported均映射UI UnsupportedRecord；CorruptRecord为失败。三种错误均不等于Missing且禁止普通configure覆盖。节点种类未知表示记录不受支持，节点结构损坏表示CorruptRecord；解码后重新执行本节字段不变量。

受保护记录读取/编码上限采用1 MiB；超限ResourceLimit，写入前完整编码检查，绝不截断保存。此限是有界存储实现常量，GUI协议仍独立64 KiB且不运送完整identity/raw。JSON键顺序可不同，但字段值按上述类型精确比较；不得用JSON文本总哈希替代canonical字段。serialize→decode→validate往返必须保持完整u64、GUID字节、UTF-16码元及摘要。记录只保存digest而不保存OptionalData原文。

### 2.2 共享合成验证表（全部待实施）

| 规则 | 正例测试 | 反例/失配测试 |
|---|---|---|
| 三节点GPT单路径 | `short_gpt_filepath_supported` | `unknown_prefix_rejected`、`multi_instance_rejected`、`extra_path_rejected`、`split_path_not_silently_normalized` |
| GPT全部字段/几何 | `hd_all_fields_roundtrip` | `partition_guid_change_rejected`、`partition_number_change_rejected`、`partition_start_change_rejected`、`partition_size_change_rejected`、`partition_range_overflow_rejected`、`mbr_or_unsigned_rejected` |
| FilePath严格码元 | `absolute_unicode_path_preserved` | `loader_path_change_rejected`、`path_case_change_mismatch`、`path_dot_or_duplicate_separator_rejected`、`relative_or_directory_only_path_rejected` |
| Description/属性独立 | `valid_description_change_preserves_identity`、`hidden_change_preserves_identity` | `malformed_description_rejected`、`inactive_target_rejected`、`reserved_load_attribute_rejected`、`unexpected_variable_attributes_rejected` |
| opaque完整含空 | `empty_optional_sha256_vector`、`sha256_known_answer_nonempty`、`opaque_non_utf16_can_register`、`same_buffer_identity_deterministic` | `opaque_body_bit_change_rejected`、`opaque_tail_nul_append_truncate_rejected`、`opaque_empty_nonempty_change_rejected` |
| 编号/分类 | `confirmed_os_with_valid_target_configures` | `missing_original_id_stops`、`id_reuse_mismatch_stops`、`unique_name_is_not_known_os`、`duplicate_identity_requires_selection` |
| 记录完整字段 | `record_v1_full_width_roundtrip`、`empty_digest_roundtrip` | `unknown_record_version_stops`、`unknown_identity_component_stops`、`unknown_algorithm_stops`、`bad_digest_or_derived_length_corrupt`、`duplicate_or_unknown_record_field_rejected`、`record_over_limit` |
| helper信任与失配 | `explicit_reconfirm_saves_new_baseline` | `gui_digest_not_trusted`、`identity_mismatch_has_no_write_reboot_save`、`unsupported_component_configure_preserves_record`、`malformed_path_even_matching_digest_rejected` |

现有私有两项/用户标签支持范围选择的观察；以上正反测试从公开格式规则人工构造，仅标synthetic。缺自然更新不阻strict exact；本节APPROVED只表示共享契约审查通过，不表示这些实现测试已经通过，测试/验收状态仍独立记录。

## 3. 1L：Linux实现输入契约（APPROVED，600aa4d）

详细官方选择沿用 [platform-contracts.md](platform-contracts.md)：efivarfs、systemd>=255、polkit>=124，Arch主环境/Ubuntu24.04参考。以下是实现及fake验收边界，不是执行任何系统操作的指令。真实授权代理、inhibitors、安装、BootNext与重启实验全部PENDING。

### 3.1 固定对象、受保护记录与锁

| 对象 | 固定边界 |
|---|---|
| helper | `/usr/lib/boothop/boothop-helper`，root可写安装对象及父目录，普通用户不可替换；不接受GUI路径/环境覆盖 |
| 可信记录 | `/var/lib/boothop/targets.json`；BootHop目录root:root 0700，记录root:root 0600；上层目录不得普通用户可写；非普通文件、symlink或异常硬链接拒绝 |
| 操作锁 | `/var/lib/boothop/operation.lock`，root:root 0600普通文件；固定持久inode，不随记录原子替换、不unlink；`flock(LOCK_EX|LOCK_NB)`，EWOULDBLOCK→Busy |
| efivarfs | 固定`/sys/firmware/efi/efivars`，目录FD验证真实efivarfs类型；仅既有全局GUID及严格Boot四位大写十六进制白名单与BootOrder/BootCurrent/BootNext；固定相对名，不接收任意路径 |

installer预建root:root 0700的BootHop目录和root:root 0600的固定持久operation.lock；安装/升级验证并保留既有有效锁inode，不unlink/替换正在使用的锁，不预写目标记录。inspect/configure/switch均只打开既有安装目录与锁，不带创建标志、不静默repair/chmod/chown安装布局。缺目录或缺锁是安装环境错误（保留open/lock阶段与errno），不是RecordState::Missing；仅布局与锁验证成功后的targets.json明确NotFound才是未配置。初装inspect因此可持锁读取Missing记录；布局损坏提示检查安装，不自动重新configure。

记录和锁通过受验证的父目录FD、no-follow打开并检查owner/mode/type/link-count；FD带CLOEXEC，锁FD保留至整次inspect/configure/switch及安全收尾结束，所有错误路径释放。锁只协调BootHop，不保护外部固件并发；位置属内部实现，不提供用户可选项。configure只可在有效布局内创建本次临时记录并原子保存，不负责创建或修复目录/锁。

save流程：锁内重新load并拒绝未知版本/组件/损坏；完整序列化<=1 MiB；同目录独占新建0600临时普通文件、完整写入并fsync；同目录原子rename替换目标，再fsync父目录。rename前失败（含临时文件fsync）返回PlatformIo并保留旧记录；rename成功后目录fsync失败必须返回独立 `Error::StoreDurabilityUnknown { raw_code: i32 }`，不能承诺旧文件还在，不自动重试configure/恢复，用户可主动inspect确认当前可见记录但不冒充已证明持久化。只清理本次已确认的私有临时文件，不删除原记录或锁文件。rename提供名字替换原子性，不等于持久化或固件事务。[Linux man-pages rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html)、[fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)（2026-09-10核对）。

### 3.2 efivarfs读取、BootNext及错误

仅O_RDONLY|O_CLOEXEC|O_NOFOLLOW读取；校验FD普通文件及所属efivarfs，拒绝路径替换/symlink/意外类型。文件最大1 MiB+4字节；4字节LE变量attributes后才是payload，完整payload按§1处理。不能将多个独立读取结果的结构字段与摘要拼成一个目标；短读/EOF要验证最终长度与边界，无法确认完整读取或检测到变化则停止，不返回部分成功。所有重试受操作截止时间约束，不无限等待。

单次枚举**保留raw的累计预算1 MiB**：所有保留Boot项与控制变量的原始buffer字节数之和（包含Linux4字节前缀），checked累计，超限ResourceLimit且不返回部分完整列表。无必要副本及时丢弃；单项读取最多1 MiB+4的临时buffer不能成为绕过累计预算的永久缓存，内存分配失败同样ResourceLimit。这是controller确认的产品限制，不是UEFI上限，与单项payload1 MiB、单份记录1 MiB、IPC总帧/累计65,536字节是四个独立计数域；不将限制扩大为1 MiB IPC。测试 `enumeration_raw_aggregate_limit_no_partial_success` 与 `single_payload_record_ipc_budgets_are_distinct`。

BootNext与BootCurrent必须**总长6字节**（4字节attributes+2字节u16 LE），不是8字节；BootOrder总长>=4且减4后为偶数，空数组可表示但不得自动选项，重复编号去重并诊断。BootNext不存在只有固定有效目录下该叶变量明确ENOENT可映射None；目标Boot#### ENOENT是目标缺失，枚举后消失不可当完整成功；记录NotFound仅在可信目录/路径检查完成后为RecordState::Missing。BootOrder/BootCurrent缺失需保留诊断，不推断BootNext能力；switch仍须原目标可读和所有实际存在控制变量结构/属性有效。

未来唯一固件修改为BootNext：Absent且冲突检查通过才写；固定全局名，fresh offset0，单次完整6字节请求（LE attributes7+u16目标），禁止追加、O_TRUNC、零字节写入或删除。已有同目标不写，只重新读回验证；其他目标终止。准备写时若对象新出现则停止重新评估，不覆盖竞态。写调用短返回/错误不拼接重试或“清理变量”，不请求重启，报告可能残留；只有完整写调用且独立读回等于目标才进入BootNextVerified。值相同不构成CAS或排除ABA，默认不恢复写入。[efivarfs格式](https://docs.kernel.org/filesystems/efivarfs.html)与[write(2)](https://man7.org/linux/man-pages/man2/write.2.html)（2026-09-10核对）；未运行这些调用。

| 错误/条件 | 结果与禁止行为 | 待实施fake测试 |
|---|---|---|
| ENOENT | 按上文上下文区分None/Missing/目标缺失/环境缺失；绝非所有错误的默认值 | `enoent_is_contextual_not_blank_success` |
| EACCES / EPERM | 平台IO错误带原errno和操作阶段；授权/安全策略失败，不当缺失，不自动提权重试固件操作 | `permission_error_not_missing` |
| EROFS | 只读环境错误并停止；不remount或清immutable，不请求重启 | `readonly_firmware_no_mount_or_write_retry` |
| ELOOP / ENOTDIR / EISDIR、metadata不符 | 拒绝路径/对象，不跟随symlink，不切换其他根目录 | `efivar_symlink_or_wrong_type_rejected` |
| EIO / ENODEV / EINVAL / 其他errno | 原码+读/写阶段保留；不能推断变量不存在或“固件未改”；写阶段错误可能残留 | `firmware_io_error_preserves_raw_code_and_stage` |
| ENOSPC / EDQUOT / ENOMEM | 存储/资源失败，停止；不删除其他变量腾空间，不自动重试写 | `firmware_capacity_failure_no_cleanup` |
| EINTR | 未产生数据的只读调用可在截止时间内重试；写请求错误不重放，保留可能残留 | `read_eintr_bounded_write_eintr_not_replayed` |
| 短buffer/错误attributes/长度 | MalformedLoadOption/UnsupportedFormat或控制值格式错误，不部分成功 | `boot_next_exact_six_bytes`、`variable_attributes_not_load_attributes` |
| 超1 MiB payload、超时或变化 | ResourceLimit或平台读取失败，不能把部分枚举当完整结果 | `efivar_over_limit_or_changed_read_rejected` |

普通IO错误统一新增窄载体 `Error::PlatformIo { operation: String, raw_code: i32 }`：operation仅允许`open/read/write/metadata/lock/fsync/rename/ipc/reboot`，不得携带变量内容/任意路径；其他安全分类沿用MalformedLoadOption、MalformedDevicePath、UnsupportedFormat、ResourceLimit、Busy、IdentityMismatch及记录错误。目标缺失作为独立失败诊断而非UnsupportedRecord/Missing配置；具体阶段随现有Report/Stage返回。底层errno取失败后立即值，不将底层IO成功推成最终OS成功。[open(2)](https://man7.org/linux/man-pages/man2/open.2.html)、[read(2)](https://man7.org/linux/man-pages/man2/read.2.html)（2026-09-10核对；错误映射为产品策略）。

StoreDurabilityUnknown是上述普通PlatformIo的明确例外：store.save→execute返回Err时保留该variant和raw_code，Report若转成诊断也必须保留该类别/码而非泛化为fsync失败；WireResponse.result的Err完整序列化/反序列化为同一Error，不改协议版本1或绕开64 KiB预算。GUI映射独立 `UiState::StoreDurabilityUnknown`，不能映射Unconfigured/Configured/UnsupportedRecord或重启UnknownResult，不宣称保存成功/旧记录保留，不自动保存、恢复、重试或触发switch。提示“配置已替换，但持久化结果未知。请先检查当前配置，勿重复保存。”

### 3.3 IPC、授权与正常重启

共享协议版本1、u32 LE长度前缀+UTF-8 JSON：请求总帧<=65,536字节，响应总帧<=65,536字节，**前缀计入**；一次操作所有响应帧（含阶段）与stderr合计<=65,536字节。超限ResourceLimit，不输出截断列表作为完整inspect，不为大description/identity另开通道。Report仅必要显示/状态/阶段；不发送原始OptionalData/完整identity或默认公开digest。可信记录的1 MiB限制不是IPC扩容。

一个request_id对应一条白名单意图：Inspect、Configure{boot_id,os}、Switch{os}；严格拒绝未知/重复字段、额外命令、GUI注入digest或路径。授权/连接等待120秒，建立后读写30秒，重启RPC回复30秒；这些是产品deadline，不承诺能中断内核固件调用。未发送操作可证明则NotAttempted；发送后断连/超时/丢终态→相关阶段Unknown，保留已知阶段/可能残留，不自动重试switch或杀进程当Rejected。

Linux启动使用固定argv `/usr/bin/pkexec --disable-internal-agent /usr/lib/boothop/boothop-helper`，无shell，无GUI控制的helper路径。helper验证euid=0、管道对象、受限环境与消息；GUI不提权/不凭PKEXEC_UID信任参数。pkexec126=取消，127=授权失败或其他错误而非确定缺agent；普通打开GUI不调用helper。[pkexec官方手册](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)沿用已核对契约。

logind固定系统总线/org/freedesktop/login1/Manager `RebootWithFlags(uint64 1)`，最低systemd255，flag仅SD_LOGIND_ROOT_CHECK_INHIBITORS，不退回Reboot/syscall/force。写BootNext前检查方法/版本支持；失败停止。明确D-Bus拒绝→Rejected；明确成功reply→Accepted；发送后丢reply/断连→Unknown，不由PrepareForShutdown信号替代关联回复。block与delay、261的block-weak分别验收；root不允许绕过，delay仍有logind自身超时。Accepted/Unknown不回滚；Rejected也不在缺CAS时写恢复值。官方v255/v257/v261来源见platform-contracts；本轮无D-Bus调用。

### 3.4 Linux完整fake清单与后续实测分离

| 功能 | 待实施正例 | 待实施拒绝/故障用例 |
|---|---|---|
| 记录目录/原子保存 | `secure_store_roundtrip` | `writable_parent_symlink_hardlink_rejected`、`unknown_record_not_overwritten`、`temp_fsync_platform_io_preserves_old`、`post_rename_dir_fsync_store_durability_unknown` |
| 安装布局/固定锁 | `installer_precreates_layout_first_inspect_reports_missing_record`、`operation_lock_held_through_flow` | `missing_lock_is_environment_error_not_missing_record`、`configure_does_not_repair_install_layout`、`upgrade_preserves_lock_inode`、`busy_lock_has_no_firmware_mutation`、`lock_fd_released_on_error`、`record_replace_does_not_replace_lock_inode` |
| 持久化错误端到端 | `store_durability_unknown_error_wire_roundtrip` | `flow_report_preserves_store_durability_unknown`、`gui_store_unknown_not_success_or_missing`、`store_unknown_no_auto_retry_restore_or_switch` |
| Linux变量 | `efivar_prefix_and_payload_separate`、`boot_next_exact_six_bytes` | §3.2全部errno/长度测试；`bootorder_empty_not_auto_target`、`enumerated_target_disappears_fails` |
| 单次BootNext写 | `absent_next_write_then_verify`、`same_next_skip_write_still_verify` | `conflicting_next_stops`、`next_write_short_no_replay_no_reboot`、`readback_mismatch_no_reboot`、`aba_does_not_authorize_restore` |
| 资源计数域 | `single_payload_record_ipc_budgets_are_distinct` | `enumeration_raw_aggregate_limit_no_partial_success`、`allocation_failure_is_resource_limit` |
| 协议/预算 | `frame_at_limit_roundtrip` | `frame_prefix_in_budget`、`cumulative_stderr_and_frames_over_limit`、`extra_request_or_duplicate_field_rejected`、`spoofed_gui_digest_rejected` |
| pkexec/断连 | `fixed_pkexec_argv_and_pipe` | `pkexec_126_cancel_127_uncertain_auth`、`helper_not_started_no_success_stage`、`disconnect_after_send_unknown_no_retry` |
| logind | `reboot_with_flags_one`、`explicit_reboot_reply_accepted` | `unsupported_logind_before_write`、`root_block_and_weak_inhibitors_reject`、`delay_wait_not_force`、`reboot_reply_lost_unknown_no_rollback` |
| 隔离/界面 | `linux_controller_uses_fake_client` | `default_tests_never_construct_real_adapter`、`windows_not_stubbed_success`、`ordinary_open_no_helper` |

flock仅advisory，不保护外部程序；选择LOCK_EX|LOCK_NB及FD生命周期依据[flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html)（Linux man-pages6.18，2026-09-10核对）。Linux桌面真实认证、root inhibitor/多会话、包安装、双向BootNext/重启/BootOrder验收均未运行且不属本次授权；fake不会解除这些真实验收要求，也不解除1W。1S.parse/1S/1L为文档APPROVED，实施状态以manifest/ledger为准；单个parser任务测试通过不等于完整1S/1L测试或aggregate Task1/Windows实证完成。
