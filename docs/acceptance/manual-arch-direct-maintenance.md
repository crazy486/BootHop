# Arch direct boot: manual partial-state inspection

The packaged setup executable currently fails closed after argument and root checks. No
production host setup adapter is enabled. These checks describe the objects an
administrator must inspect if a future setup run stops after a mutation. They do not
authorize automatic cleanup. Do not infer success or ownership from a label or from a
single file's presence.

## Read-only inventory

Keep the normal Boot0000 GRUB path available. Record the selected kernel flavor and
the exact contents and metadata of its existing
`/etc/mkinitcpio.d/<flavor>.preset`. Check whether PRESETS contains one `boothop`
stanza, whether `boothop_uki` points to the stage beside
`EFI/BootHop/arch.efi`, and whether `boothop_cmdline` is exactly
`/etc/kernel/cmdline`. Compare the default and fallback lines against a known
pre-setup copy or the installed package's expected preset. Do not edit another flavor.

Inspect `/etc/initcpio/post/boothop-uki` as data: ownership, mode, symlink
status, and exact command. A valid installed hook must call only
`/usr/lib/boothop/boothop-uki-publish` with a fixed mode and the selected
stage path. Check that publisher's root ownership and lack of group or world write
permission. Inspect the mounted vfat ESP and its GPT partition identity before
reading `EFI/BootHop/arch.efi` and `arch.efi.tmp`; check each path component
for symlinks. Record presence, size, and hashes. A syntactically valid PE image is
not evidence that it boots.

Read `/var/lib/boothop/arch-direct.identity` without changing it. Its only
supported bytes are the four canonical lines `BOOTHOP_ARCH_V1`,
`boot_id=XXXX`, `option_sha256=<64 lowercase hex>`, and
`path=EFI/BootHop/arch.efi`, each ending with a newline. The marker may be
absent if setup stopped before its final save. A malformed or foreign marker
must be treated as unknown ownership.

Use firmware read commands only, such as `efibootmgr -v`, to capture the full
BootOrder, BootNext, Boot0000, and every Boot#### including entries absent from
BootOrder. For a proposed BootHop entry, compare its complete EFI load-option
bytes or a trusted parser's canonical identity: active attribute, GPT HD()
partition number/start/size/GUID, fixed File() path
`\\EFI\\BootHop\\arch.efi`, description `BootHop Arch`, and empty OptionalData.
Compare the exact bytes' SHA-256 with the marker when present. Record unknown
reads explicitly. BootNext must be absent before any future setup attempt.

## Publisher stage freshness boundary

The publisher validates the staged UKI and checks that the file remains stable
while it validates and renames it. It does not independently prove when the
stage was generated. The supported mkinitcpio path calls the BootHop post hook
for the selected preset after successful UKI generation; initial setup also
removes a pre-existing stage before the build. A root administrator who invokes
the publisher directly with an old, valid stage and matching arguments could
still publish that old image. This direct root invocation is accepted within
the current root-only trust model while real setup remains disabled. Do not
invoke the publisher directly or treat a leftover stage as evidence of a
successful build. Any future change to this trust boundary needs a separate
review before real setup is enabled.

## Administrator-controlled cleanup

First preserve the inventory above and verify the original Boot0000 and BootOrder.
If a setup stopped after the preset edit or hook installation, a later kernel update
may fail closed because the marker is absent. An administrator may restore only the
selected preset from a verified pre-setup copy and remove only a hook whose exact
content and inode ownership are established. Inspect the staged and final BootHop
files separately before any manual removal. Do not delete either based on its name
alone.

If a Boot#### was created, identify it by exact variable name, load-option bytes,
GPT identity, fixed path, and saved digest if available. Check the current
BootOrder and BootNext again immediately before a manual firmware command. A
short or uncertain prior write can leave an entry or a trailing order item.
The administrator must decide whether and how to remove precisely that entry;
never delete by the `BootHop Arch` label alone, never modify Boot0000, and
never reorder existing GRUB or Windows entries. This project provides no
automatic rollback or uninstall.

Removing the BootHop package does not uninstall an Arch setup. If the preset and
post hook still refer to the packaged publisher, later kernel updates will fail
until an administrator completes the inspection and manual maintenance above.
After any failed update, rebuild and boot-test the direct path in isolation
before relying on a Windows one-time switch: the old UKI may refer to modules
that the update removed.
