#[cfg(target_os = "linux")]
mod linux {
    use boothop_core::{BootId, Classification, Os};
    use boothop_gui::{
        cache::{Cache, LinuxCache, safe_description},
        controller::{Controller, Executor, Helper, ThreadExecutor, UiIntent},
        helper_client::{HelperClient, linux::SystemProcess},
        ui::{AppWindow, CandidateRow},
    };
    use slint::{ComponentHandle, ModelRc, VecModel};
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    fn render<H: Helper, E: Executor, C: Cache>(ui: &AppWindow, c: &Controller<H, E, C>) {
        ui.set_status_text(c.status().into());
        ui.set_target_text(
            c.target()
                .map_or_else(
                    || "目标：尚无可显示的记录信息".into(),
                    |target| {
                        format!(
                            "目标（展示信息）：Boot{:04X} / {:?} / {}",
                            target.boot_id.0,
                            target.os,
                            safe_description(
                                target.description_utf16.as_deref().unwrap_or_default()
                            )
                        )
                    },
                )
                .into(),
        );
        // Copyable diagnostics exclude names and any firmware/identity data.
        ui.set_diagnostic_text(
            format!(
                "{}{}",
                c.target().map_or_else(String::new, |t| format!(
                    "Boot{:04X} / {:?}；",
                    t.boot_id.0, t.os
                )),
                c.diagnostic()
            )
            .into(),
        );
        ui.set_cache_warning(
            if c.cache_warning().is_some() {
                "展示缓存读写失败；不会自动重复配置。"
            } else {
                ""
            }
            .into(),
        );
        ui.set_inspect_enabled(c.can_inspect());
        ui.set_switch_enabled(c.can_switch());
        ui.set_configuration_visible(c.configuration_visible());
        ui.set_configure_enabled(c.can_configure());
        ui.set_selection_enabled(c.can_select());
        ui.set_confirmation_enabled(c.can_select() && c.selected().is_some());
        ui.set_target_confirmed(c.confirmed());
        ui.set_target_os_name("Windows".into());
        ui.set_candidates(ModelRc::new(VecModel::from(
            c.candidates()
                .iter()
                .map(|candidate| CandidateRow {
                    boot_id: i32::from(candidate.boot_id.0),
                    label: format!(
                        "Boot{:04X}  {}  · {} · {}",
                        candidate.boot_id.0,
                        safe_description(&candidate.description_utf16),
                        if candidate.classification == Classification::Unsupported {
                            "结构不支持"
                        } else {
                            "结构支持，需确认"
                        },
                        if candidate.ambiguous {
                            "有歧义：必须人工选择确认"
                        } else {
                            "无歧义"
                        }
                    )
                    .into(),
                    supported: candidate.classification != Classification::Unsupported,
                    selected: c.selected() == Some(candidate.boot_id),
                })
                .collect::<Vec<_>>(),
        )));
    }

    pub fn run() -> Result<(), slint::PlatformError> {
        // Fix the approved runtime backend/renderer rather than taking renderer overrides.
        slint::BackendSelector::new()
            .backend_name("winit".into())
            .renderer_name("femtovg".into())
            .select()?;
        let ui = AppWindow::new()?;
        let weak = ui.as_weak();
        let wake = Arc::new(move || {
            let _ = weak.upgrade_in_event_loop(|ui| ui.invoke_completed());
        });
        let cache = LinuxCache::from_environment(
            std::env::var_os("XDG_STATE_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        );
        // This constructor only reads local cache. A new process boundary is lazy until run(Request).
        let controller = Rc::new(RefCell::new(Controller::new(
            HelperClient::<SystemProcess>::system(),
            ThreadExecutor,
            cache,
            wake,
            Os::Windows,
        )));
        render(&ui, &controller.borrow());
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_completed(move || {
                c.borrow_mut().poll();
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_inspect(move || {
                c.borrow_mut().handle(UiIntent::Inspect);
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_switch_target(move || {
                c.borrow_mut().handle(UiIntent::Switch);
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_select_target(move |id| {
                if let Ok(id) = u16::try_from(id) {
                    c.borrow_mut().select(BootId(id));
                }
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_confirm_target(move |confirmed| {
                c.borrow_mut().confirm_target(confirmed);
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller;
            let weak = ui.as_weak();
            ui.on_configure(move || {
                let selected = c.borrow().selected();
                if let Some(id) = selected {
                    c.borrow_mut().handle(UiIntent::Configure(id, Os::Windows));
                }
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        ui.run()
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), slint::PlatformError> {
    linux::run()
}

#[cfg(windows)]
mod windows {
    use boothop_core::{BootId, Classification, Os};
    use boothop_gui::{
        cache::{Cache, WindowsCache, safe_description},
        controller::{Controller, Executor, Helper, ThreadExecutor, UiIntent},
        helper_client::windows::WindowsClient,
        ui::{AppWindow, CandidateRow},
    };
    use slint::{ComponentHandle, ModelRc, VecModel};
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    fn render<H: Helper, E: Executor, C: Cache>(ui: &AppWindow, c: &Controller<H, E, C>) {
        ui.set_status_text(c.status().into());
        ui.set_target_text(
            c.target()
                .map_or_else(
                    || "目标：尚无可显示的记录信息".into(),
                    |target| {
                        format!(
                            "目标（展示信息）：Boot{:04X} / {:?} / {}",
                            target.boot_id.0,
                            target.os,
                            safe_description(
                                target.description_utf16.as_deref().unwrap_or_default()
                            )
                        )
                    },
                )
                .into(),
        );
        ui.set_diagnostic_text(
            format!(
                "{}{}",
                c.target().map_or_else(String::new, |t| format!(
                    "Boot{:04X} / {:?}；",
                    t.boot_id.0, t.os
                )),
                c.diagnostic()
            )
            .into(),
        );
        ui.set_cache_warning(
            if c.cache_warning().is_some() {
                "展示缓存读写失败；不会自动重复配置。"
            } else {
                ""
            }
            .into(),
        );
        ui.set_inspect_enabled(c.can_inspect());
        ui.set_switch_enabled(c.can_switch());
        ui.set_configuration_visible(c.configuration_visible());
        ui.set_configure_enabled(c.can_configure());
        ui.set_selection_enabled(c.can_select());
        ui.set_confirmation_enabled(c.can_select() && c.selected().is_some());
        ui.set_target_confirmed(c.confirmed());
        ui.set_target_os_name("Linux".into());
        ui.set_candidates(ModelRc::new(VecModel::from(
            c.candidates()
                .iter()
                .map(|candidate| CandidateRow {
                    boot_id: i32::from(candidate.boot_id.0),
                    label: format!(
                        "Boot{:04X}  {}  · {} · {}",
                        candidate.boot_id.0,
                        safe_description(&candidate.description_utf16),
                        if candidate.classification == Classification::Unsupported {
                            "结构不支持"
                        } else {
                            "结构支持，需确认"
                        },
                        if candidate.ambiguous {
                            "有歧义：必须人工选择确认"
                        } else {
                            "无歧义"
                        }
                    )
                    .into(),
                    supported: candidate.classification != Classification::Unsupported,
                    selected: c.selected() == Some(candidate.boot_id),
                })
                .collect::<Vec<_>>(),
        )));
    }

    pub fn run() -> Result<(), slint::PlatformError> {
        slint::BackendSelector::new()
            .backend_name("winit".into())
            .renderer_name("femtovg".into())
            .select()?;
        let ui = AppWindow::new()?;
        let weak = ui.as_weak();
        let wake = Arc::new(move || {
            let _ = weak.upgrade_in_event_loop(|ui| ui.invoke_completed());
        });
        let cache = WindowsCache::from_local_app_data();
        let controller = Rc::new(RefCell::new(Controller::new(
            WindowsClient::system(),
            ThreadExecutor,
            cache,
            wake,
            Os::Linux,
        )));
        render(&ui, &controller.borrow());
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_completed(move || {
                c.borrow_mut().poll();
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_inspect(move || {
                c.borrow_mut().handle(UiIntent::Inspect);
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_switch_target(move || {
                c.borrow_mut().handle(UiIntent::Switch);
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_select_target(move |id| {
                if let Ok(id) = u16::try_from(id) {
                    c.borrow_mut().select(BootId(id));
                }
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller.clone();
            let weak = ui.as_weak();
            ui.on_confirm_target(move |confirmed| {
                c.borrow_mut().confirm_target(confirmed);
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        {
            let c = controller;
            let weak = ui.as_weak();
            ui.on_configure(move || {
                let selected = c.borrow().selected();
                if let Some(id) = selected {
                    c.borrow_mut().handle(UiIntent::Configure(id, Os::Linux));
                }
                if let Some(ui) = weak.upgrade() {
                    render(&ui, &c.borrow());
                }
            });
        }
        ui.run()
    }
}

#[cfg(windows)]
fn main() -> Result<(), slint::PlatformError> {
    windows::run()
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn main() -> Result<(), &'static str> {
    Err("BootHop desktop wiring is currently available on Linux and Windows only")
}
