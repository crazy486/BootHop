#[test]
fn single_window_declares_required_actions_and_unconditional_warning() {
    let ui =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/main.slint")).unwrap();
    assert_eq!(ui.matches("inherits Window").count(), 1);
    for text in [
        "点击后将立即重启，请先保存工作",
        "重启进入 Windows",
        "我确认所选目标是 Windows",
        "检查启动配置",
        "配置所选目标",
        "复制诊断",
    ] {
        assert!(ui.contains(text), "missing {text}");
    }
    assert!(!ui.contains("已进入 Windows"));
}
#[test]
fn slint_is_explicitly_pinned_and_exclusive_to_gui() {
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    assert!(manifest.contains("slint = { version = \"=1.17.1\", default-features = false"));
    assert!(manifest.contains("slint-build = { version = \"=1.17.1\", default-features = false"));
    for feature in [
        "backend-winit",
        "backend-winit-wayland",
        "backend-winit-x11",
        "renderer-femtovg",
    ] {
        assert!(manifest.contains(feature));
    }
    for forbidden in ["renderer-software", "renderer-skia", "backend-default"] {
        assert!(!manifest.contains(forbidden));
    }
    for name in ["core", "platform", "helper"] {
        let manifest = std::fs::read_to_string(format!(
            "{}/../{name}/Cargo.toml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert!(!manifest.contains("slint"));
    }
}

#[test]
fn linux_entry_point_wires_explicit_callbacks_and_event_loop_completions() {
    let main =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")).unwrap();
    for boundary in [
        "on_inspect",
        "on_switch_target",
        "on_select_target",
        "on_confirm_windows",
        "on_configure",
        "on_completed",
        "upgrade_in_event_loop",
        "ThreadExecutor",
    ] {
        assert!(main.contains(boundary), "missing {boundary}");
    }
}

#[test]
fn windows_entry_point_wires_helper_client_and_untrusted_local_cache_only() {
    let main =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")).unwrap();
    for boundary in [
        "#[cfg(windows)]",
        "WindowsClient::system()",
        "WindowsCache::from_local_app_data()",
        "on_inspect",
        "on_switch_target",
        "on_configure",
    ] {
        assert!(main.contains(boundary), "missing {boundary}");
    }
    for forbidden in [
        "GetFirmwareEnvironmentVariable",
        "SetFirmwareEnvironmentVariable",
        "AdjustTokenPrivileges",
        "InitiateSystemShutdown",
        "bcdedit",
        "CreateProcess",
        "ShellExecute",
        "std::process::",
    ] {
        assert!(
            !main.contains(forbidden),
            "forbidden GUI capability {forbidden}"
        );
    }
}

#[test]
fn gui_source_has_no_native_mutation_capability_or_platform_dependency() {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let forbidden = [
        "getfirmwareenvironmentvariable",
        "setfirmwareenvironmentvariable",
        "adjusttokenprivileges",
        "initiatesystemshutdown",
        "exitwindows",
        "bcd",
        "loadlibrary",
        "getprocaddress",
        "createprocess",
    ];
    fn visit(path: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    visit(root, &mut files);
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap().to_ascii_lowercase();
        for needle in forbidden {
            assert!(!source.contains(needle), "{needle} in {}", path.display());
        }
        if source.contains("shellexecute") {
            assert!(path.ends_with("helper_client/windows/native.rs"));
        }
    }
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .unwrap()
        .to_ascii_lowercase();
    assert!(!manifest.contains("boothop-platform"));
}
