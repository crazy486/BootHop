//! Syntax-level audit for code compiled as tests.
//!
//! This intentionally does not try to be a Rust type checker. It parses the
//! same source that rustc sees, resolves import/type aliases that can be
//! resolved locally, and fails closed for operations that can cross BootHop's
//! process, firmware, system-bus, or desktop boundaries. The audit is a CI
//! guard, not a proof that arbitrary unsafe code is impossible.

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
};

use syn::{
    Attribute, Expr, ExprCall, ExprLit, ExprMacro, ExprMethodCall, ExprPath, File, Item, ItemMod,
    Lit, Meta, Type, UseTree,
    visit::{self, Visit},
};

type AliasMap = HashMap<String, Vec<String>>;

#[derive(Debug)]
struct Issue {
    file: String,
    message: String,
}

#[derive(Default)]
struct AuditState {
    issues: Vec<Issue>,
    visited_modules: HashSet<PathBuf>,
    dangerous_functions: HashSet<String>,
}

fn main() {
    let mut root = PathBuf::from(".");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                root = args
                    .next()
                    .unwrap_or_else(|| usage("--root needs a path"))
                    .into();
            }
            "-h" | "--help" => {
                println!("usage: boothop-isolation-audit [--root PATH]");
                return;
            }
            other => usage(&format!("unknown argument {other}")),
        }
    }

    if let Err(issues) = audit_tree(&root) {
        for issue in issues {
            eprintln!("{}: {}", issue.file, issue.message);
        }
        std::process::exit(1);
    }
}

fn usage(message: &str) -> ! {
    eprintln!("{message}\nusage: boothop-isolation-audit [--root PATH]");
    std::process::exit(64);
}

fn audit_tree(root: &Path) -> Result<usize, Vec<Issue>> {
    let root = match root.canonicalize() {
        Ok(root) => root,
        Err(error) => {
            return Err(vec![Issue {
                file: root.display().to_string(),
                message: format!("cannot resolve audit root: {error}"),
            }]);
        }
    };
    let mut files = Vec::new();
    if let Err(message) = collect_rs(&root.join("crates"), &mut files) {
        return Err(vec![Issue {
            file: root.display().to_string(),
            message,
        }]);
    }
    if files.is_empty() {
        return Err(vec![Issue {
            file: root.display().to_string(),
            message: "no Rust sources found under crates".into(),
        }]);
    }

    let mut state = AuditState::default();
    let mut parsed = HashMap::<PathBuf, File>::new();
    for path in &files {
        match fs::read_to_string(path) {
            Ok(source) => match syn::parse_file(&source) {
                Ok(file) => {
                    parsed.insert(path.clone(), file);
                }
                Err(error) => state.issues.push(Issue {
                    file: path.display().to_string(),
                    message: format!("cannot parse Rust source: {error}"),
                }),
            },
            Err(error) => state.issues.push(Issue {
                file: path.display().to_string(),
                message: format!("cannot read Rust source: {error}"),
            }),
        }
    }
    if !state.issues.is_empty() {
        return Err(state.issues);
    }

    for path in &mut files {
        *path = path.canonicalize().map_err(|error| {
            vec![Issue {
                file: path.display().to_string(),
                message: format!("cannot resolve Rust source: {error}"),
            }]
        })?;
    }
    state.dangerous_functions = collect_dangerous_functions(&parsed);
    for path in &files {
        let Some(file) = parsed.get(path) else {
            continue;
        };
        let external_test = path.components().any(|part| part.as_os_str() == "tests");
        if external_test {
            audit_test_items(
                &file.items,
                path,
                &root,
                &AliasMap::new(),
                &parsed,
                &mut state,
            );
        } else {
            audit_cfg_modules(
                &file.items,
                path,
                &root,
                &AliasMap::new(),
                &parsed,
                &mut state,
            );
        }
    }
    if state.issues.is_empty() {
        Ok(files.len())
    } else {
        Err(state.issues)
    }
}

fn collect_dangerous_functions(parsed: &HashMap<PathBuf, File>) -> HashSet<String> {
    let mut dangerous = HashSet::new();
    loop {
        let known = dangerous.clone();
        let mut additions = HashSet::new();
        for (path, file) in parsed {
            let mut aliases = AliasMap::new();
            collect_aliases(&file.items, &mut aliases);
            collect_nested_aliases(&file.items, &mut aliases);
            let mut probe = FunctionProbe {
                aliases: &aliases,
                source_path: path,
                known_dangerous: &known,
                additions: &mut additions,
            };
            probe.visit_file(file);
        }
        let previous = dangerous.len();
        dangerous.extend(additions);
        if dangerous.len() == previous {
            return dangerous;
        }
    }
}

struct FunctionProbe<'a> {
    aliases: &'a AliasMap,
    source_path: &'a Path,
    known_dangerous: &'a HashSet<String>,
    additions: &'a mut HashSet<String>,
}

impl FunctionProbe<'_> {
    fn body_is_dangerous(&mut self, name: &syn::Ident, block: &syn::Block) {
        let mut issues = Vec::new();
        let mut visitor = ExprAudit {
            aliases: self.aliases,
            source_path: self.source_path,
            issues: &mut issues,
            dangerous_functions: self.known_dangerous,
            tainted_bindings: HashSet::new(),
            boot_order_bindings: HashSet::new(),
        };
        visitor.visit_block(block);
        if !issues.is_empty() {
            self.additions.insert(name.to_string());
        }
    }
}

impl Visit<'_> for FunctionProbe<'_> {
    fn visit_item_fn(&mut self, item: &syn::ItemFn) {
        self.body_is_dangerous(&item.sig.ident, &item.block);
        visit::visit_item_fn(self, item);
    }
}

fn collect_rs(dir: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "symlink in audited source tree: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_rs(&path, output)?;
        } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            output.push(path);
        }
    }
    Ok(())
}

fn audit_cfg_modules(
    items: &[Item],
    source_path: &Path,
    root: &Path,
    inherited: &AliasMap,
    parsed: &HashMap<PathBuf, File>,
    state: &mut AuditState,
) {
    let mut aliases = inherited.clone();
    collect_aliases(items, &mut aliases);
    for item in items {
        let Item::Mod(module) = item else { continue };
        if has_test_cfg(&module.attrs) {
            audit_test_module(module, source_path, root, &aliases, parsed, state);
        } else if let Some((_, nested)) = &module.content {
            audit_cfg_modules(nested, source_path, root, &aliases, parsed, state);
        } else if module_file_path(module, source_path).is_some() {
            // A production external module may contain a nested cfg(test)
            // module. Parse it so nested attributes are not missed.
            if let Some((path, file)) = load_module(module, source_path, root, parsed, state) {
                audit_cfg_modules(&file.items, &path, root, &aliases, parsed, state);
            }
        }
    }
}

fn audit_test_module(
    module: &ItemMod,
    source_path: &Path,
    root: &Path,
    inherited: &AliasMap,
    parsed: &HashMap<PathBuf, File>,
    state: &mut AuditState,
) {
    if let Some((_, items)) = &module.content {
        audit_test_items(items, source_path, root, inherited, parsed, state);
        return;
    }
    if module_file_path(module, source_path).is_none() {
        state.issues.push(Issue {
            file: source_path.display().to_string(),
            message: format!("cannot determine cfg(test) module path: {}", module.ident),
        });
        return;
    }
    let Some((path, file)) = load_module(module, source_path, root, parsed, state) else {
        return;
    };
    audit_test_items(&file.items, &path, root, inherited, parsed, state);
}

fn audit_test_items(
    items: &[Item],
    source_path: &Path,
    root: &Path,
    inherited: &AliasMap,
    parsed: &HashMap<PathBuf, File>,
    state: &mut AuditState,
) {
    let mut aliases = inherited.clone();
    collect_aliases(items, &mut aliases);
    collect_nested_aliases(items, &mut aliases);
    let mut visitor = ExprAudit {
        aliases: &aliases,
        source_path,
        issues: &mut state.issues,
        dangerous_functions: &state.dangerous_functions,
        tainted_bindings: HashSet::new(),
        boot_order_bindings: HashSet::new(),
    };
    for item in items {
        visit::Visit::visit_item(&mut visitor, item);
    }
    for item in items {
        let Item::Mod(module) = item else { continue };
        // A nested module inside a test module is test-compiled regardless of
        // whether it repeats cfg(test); recurse through both forms.
        if module.content.is_some() || has_test_cfg(&module.attrs) {
            audit_test_module(module, source_path, root, &aliases, parsed, state);
        } else if module_file_path(module, source_path).is_some() {
            let Some((path, file)) = load_module(module, source_path, root, parsed, state) else {
                continue;
            };
            audit_test_items(&file.items, &path, root, &aliases, parsed, state);
        }
    }
}

fn collect_nested_aliases(items: &[Item], aliases: &mut AliasMap) {
    struct Collector<'a> {
        aliases: &'a mut AliasMap,
    }
    impl Visit<'_> for Collector<'_> {
        fn visit_item_use(&mut self, item: &syn::ItemUse) {
            collect_use_tree(None, &item.tree, self.aliases);
            visit::visit_item_use(self, item);
        }

        fn visit_item_type(&mut self, item: &syn::ItemType) {
            if let Type::Path(type_path) = &*item.ty
                && let Some(path) = resolve_path(&type_path.path, self.aliases)
            {
                self.aliases.insert(item.ident.to_string(), path);
            }
            visit::visit_item_type(self, item);
        }
    }
    let mut collector = Collector { aliases };
    for item in items {
        collector.visit_item(item);
    }
}

fn load_module<'a>(
    module: &ItemMod,
    source_path: &Path,
    root: &Path,
    parsed: &'a HashMap<PathBuf, File>,
    state: &mut AuditState,
) -> Option<(PathBuf, &'a File)> {
    let path = module_file_path(module, source_path)?;
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            state.issues.push(Issue {
                file: source_path.display().to_string(),
                message: format!("cannot resolve cfg(test) module {}: {error}", module.ident),
            });
            return None;
        }
    };
    if !canonical.starts_with(root) {
        state.issues.push(Issue {
            file: source_path.display().to_string(),
            message: format!(
                "cfg(test) module escapes audit root: {}",
                canonical.display()
            ),
        });
        return None;
    }
    if !state.visited_modules.insert(canonical.clone()) {
        return None;
    }
    parsed
        .get(&canonical)
        .map(|file| (canonical.clone(), file))
        .or_else(|| {
            state.issues.push(Issue {
                file: source_path.display().to_string(),
                message: format!(
                    "cfg(test) module is not an audited Rust file: {}",
                    canonical.display()
                ),
            });
            None
        })
}

fn module_file_path(module: &ItemMod, source_path: &Path) -> Option<PathBuf> {
    let directory = source_path.parent()?;
    for attr in &module.attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        let Meta::NameValue(value) = &attr.meta else {
            continue;
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Str(path),
            ..
        }) = &value.value
        else {
            return None;
        };
        return Some(directory.join(path.value()));
    }
    let file_name = source_path.file_name()?.to_str()?;
    let module_directory = if matches!(file_name, "lib.rs" | "main.rs")
        || source_path
            .components()
            .any(|part| part.as_os_str() == "tests")
    {
        directory.to_path_buf()
    } else {
        directory.join(source_path.file_stem()?)
    };
    let plain = module_directory.join(format!("{}.rs", module.ident));
    if plain.exists() {
        Some(plain)
    } else {
        Some(
            module_directory
                .join(module.ident.to_string())
                .join("mod.rs"),
        )
    }
}

fn has_test_cfg(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let name = attr
            .path()
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        match name.as_deref() {
            Some("cfg") => meta_contains_test(&attr.meta),
            Some("cfg_attr") => meta_contains_test_attr(&attr.meta),
            _ => false,
        }
    })
}

fn meta_contains_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::NameValue(value) => value.path.is_ident("test"),
        Meta::List(list) => {
            let parser = syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated;
            let Ok(nested) = syn::parse::Parser::parse2(parser, list.tokens.clone()) else {
                return false;
            };
            nested.iter().any(meta_contains_test)
        }
    }
}

fn meta_contains_test_attr(meta: &Meta) -> bool {
    let Meta::List(list) = meta else { return false };
    let parser = syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated;
    let Ok(nested) = syn::parse::Parser::parse2(parser, list.tokens.clone()) else {
        return false;
    };
    nested.first().is_some_and(meta_contains_test)
}

fn collect_aliases(items: &[Item], aliases: &mut AliasMap) {
    for item in items {
        match item {
            Item::Use(item_use) => collect_use_tree(None, &item_use.tree, aliases),
            Item::ExternCrate(item_crate) => {
                let alias = item_crate
                    .rename
                    .as_ref()
                    .map(|(_, name)| name.to_string())
                    .unwrap_or_else(|| item_crate.ident.to_string());
                aliases.insert(alias, vec![item_crate.ident.to_string()]);
            }
            Item::Type(item_type) => {
                if let Type::Path(type_path) = &*item_type.ty
                    && let Some(path) = resolve_path(&type_path.path, aliases)
                {
                    aliases.insert(item_type.ident.to_string(), path);
                }
            }
            _ => {}
        }
    }
}

fn collect_use_tree(prefix: Option<Vec<String>>, tree: &UseTree, aliases: &mut AliasMap) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix.unwrap_or_default();
            next.push(path.ident.to_string());
            collect_use_tree(Some(next), &path.tree, aliases);
        }
        UseTree::Name(name) => {
            let mut full = prefix.unwrap_or_default();
            full.push(name.ident.to_string());
            aliases.insert(name.ident.to_string(), full);
        }
        UseTree::Rename(rename) => {
            let mut full = prefix.unwrap_or_default();
            full.push(rename.ident.to_string());
            aliases.insert(rename.rename.to_string(), full);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(prefix.clone(), item, aliases);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn resolve_path(path: &syn::Path, aliases: &AliasMap) -> Option<Vec<String>> {
    let mut segments = path.segments.iter();
    let first = segments.next()?.ident.to_string();
    let mut result = aliases.get(&first).cloned().unwrap_or_else(|| vec![first]);
    let mut expanded = HashSet::new();
    while let Some(head) = result.first().cloned() {
        if !expanded.insert(head.clone()) {
            break;
        }
        let Some(replacement) = aliases.get(&head) else {
            break;
        };
        let mut next = replacement.clone();
        next.extend(result.into_iter().skip(1));
        result = next;
    }
    for segment in segments {
        result.push(segment.ident.to_string());
    }
    Some(result)
}

struct PathTaint<'a> {
    tainted_bindings: &'a HashSet<String>,
    found: bool,
}

impl Visit<'_> for PathTaint<'_> {
    fn visit_expr_lit(&mut self, expr: &ExprLit) {
        if let Lit::Str(value) = &expr.lit {
            self.found |= is_system_path(value.value().as_str());
        }
        visit::visit_expr_lit(self, expr);
    }

    fn visit_expr_path(&mut self, expr: &ExprPath) {
        if expr
            .path
            .segments
            .first()
            .is_some_and(|segment| self.tainted_bindings.contains(&segment.ident.to_string()))
        {
            self.found = true;
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_macro(&mut self, expr: &ExprMacro) {
        let text = expr.mac.tokens.to_string();
        self.found |= is_system_path(&text)
            || text
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|name| self.tainted_bindings.contains(name));
        visit::visit_expr_macro(self, expr);
    }
}

struct BootOrderTaint<'a> {
    boot_order_bindings: &'a HashSet<String>,
    found: bool,
}

impl Visit<'_> for BootOrderTaint<'_> {
    fn visit_expr_lit(&mut self, expr: &ExprLit) {
        if let Lit::Str(value) = &expr.lit {
            self.found |=
                value.value().contains("BootOrder") || value.value().contains("BootCurrent");
        }
        visit::visit_expr_lit(self, expr);
    }

    fn visit_expr_path(&mut self, expr: &ExprPath) {
        if expr.path.segments.first().is_some_and(|segment| {
            self.boot_order_bindings
                .contains(&segment.ident.to_string())
        }) {
            self.found = true;
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_macro(&mut self, expr: &ExprMacro) {
        let text = expr.mac.tokens.to_string();
        self.found |= text.contains("BootOrder") || text.contains("BootCurrent");
        visit::visit_expr_macro(self, expr);
    }
}

struct ExprAudit<'a> {
    aliases: &'a AliasMap,
    source_path: &'a Path,
    issues: &'a mut Vec<Issue>,
    dangerous_functions: &'a HashSet<String>,
    tainted_bindings: HashSet<String>,
    boot_order_bindings: HashSet<String>,
}

impl ExprAudit<'_> {
    fn report(&mut self, message: impl Into<String>) {
        let file = self.source_path.display().to_string();
        let message = message.into();
        if !self
            .issues
            .iter()
            .any(|issue| issue.file == file && issue.message == message)
        {
            self.issues.push(Issue { file, message });
        }
    }

    fn path(&self, path: &syn::Path) -> Vec<String> {
        resolve_path(path, self.aliases).unwrap_or_default()
    }

    fn check_path(&mut self, path: &syn::Path, args: Option<&[Expr]>) {
        let canonical = self.path(path);
        if is_process_command(&canonical) {
            self.report("test code references std::process::Command");
            return;
        }
        if is_system_bus_path(&canonical) {
            self.report("test code references a zbus system/session connection or proxy");
            return;
        }
        if is_libc_system_call(&canonical) {
            self.report("test code references a libc process/reboot/system call");
            return;
        }
        if is_slint_boundary(&canonical) {
            self.report("test code references a Slint event loop or window boundary");
            return;
        }
        if is_production_constructor(&canonical) {
            self.report(
                "test code references a production adapter or installed helper constructor",
            );
            return;
        }
        if canonical
            .last()
            .is_some_and(|name| self.dangerous_functions.contains(name))
        {
            self.report("test code calls a wrapper whose body crosses a protected system boundary");
            return;
        }
        if is_filesystem_path_api(&canonical)
            && args.is_some_and(|args| args.iter().any(|arg| self.has_system_path(arg)))
        {
            self.report("test code accesses a protected system path through a filesystem API");
        }
        if is_libc_path_api(&canonical)
            && args.is_some_and(|args| args.iter().any(|arg| self.has_system_path(arg)))
        {
            self.report("test code accesses a protected system path through a libc API");
        }
    }

    fn has_system_path(&self, expr: &Expr) -> bool {
        let mut visitor = PathTaint {
            tainted_bindings: &self.tainted_bindings,
            found: false,
        };
        visitor.visit_expr(expr);
        visitor.found
    }

    fn command_receiver(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(path) => is_process_command(&self.path(&path.path)),
            Expr::Call(call) => match &*call.func {
                Expr::Path(path) => is_process_command(&self.path(&path.path)),
                _ => false,
            },
            Expr::MethodCall(call) => self.command_receiver(&call.receiver),
            Expr::Paren(paren) => self.command_receiver(&paren.expr),
            Expr::Group(group) => self.command_receiver(&group.expr),
            _ => false,
        }
    }

    fn has_boot_order(&self, expr: &Expr) -> bool {
        let mut visitor = BootOrderTaint {
            boot_order_bindings: &self.boot_order_bindings,
            found: false,
        };
        visitor.visit_expr(expr);
        visitor.found
    }
}

impl Visit<'_> for ExprAudit<'_> {
    fn visit_expr_call(&mut self, call: &ExprCall) {
        if let Expr::Path(path) = &*call.func {
            let args = call.args.iter().cloned().collect::<Vec<_>>();
            self.check_path(&path.path, Some(&args));
            if is_unqualified_dangerous_wrapper(&self.path(&path.path)) {
                self.report("test code calls an unresolved process/system wrapper");
            }
            if self
                .path(&path.path)
                .last()
                .is_some_and(|name| name == "write_next")
                && args.iter().any(|arg| self.has_boot_order(arg))
            {
                self.report("fake write assertion may target BootNext only");
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &ExprMethodCall) {
        if self.command_receiver(&call.receiver)
            && matches!(
                call.method.to_string().as_str(),
                "spawn" | "status" | "output" | "wait"
            )
        {
            self.report("test code executes a std::process::Command");
        }
        if call.method == "write_next" && call.args.iter().any(|arg| self.has_boot_order(arg)) {
            self.report("fake write assertion may target BootNext only");
        }
        if let Expr::Path(path) = &*call.receiver {
            let canonical = self.path(&path.path);
            let args = call.args.iter().cloned().collect::<Vec<_>>();
            if is_filesystem_path_api(&canonical)
                && args.iter().any(|arg| self.has_system_path(arg))
            {
                self.report("test code accesses a protected system path through a filesystem API");
            }
        }
        if matches!(
            call.method.to_string().as_str(),
            "open"
                | "read"
                | "read_to_string"
                | "write"
                | "write_all"
                | "remove_file"
                | "remove_dir"
                | "remove_dir_all"
                | "create_dir"
                | "create_dir_all"
                | "rename"
                | "copy"
                | "push"
                | "set_file_name"
        ) && call.args.iter().any(|arg| self.has_system_path(arg))
        {
            self.report("test code accesses a protected system path through a filesystem API");
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_macro(&mut self, expr: &ExprMacro) {
        let canonical = self.path(&expr.mac.path);
        if !is_allowed_test_macro(&canonical) {
            self.report("test code invokes an unallowlisted macro that cannot be audited");
        }
        if canonical.last().is_some_and(|name| name == "include_str")
            && is_system_path(&expr.mac.tokens.to_string())
        {
            self.report("test code includes a protected system path through a macro");
        }
        visit::visit_expr_macro(self, expr);
    }

    fn visit_item_macro(&mut self, item: &syn::ItemMacro) {
        let canonical = self.path(&item.mac.path);
        if !is_allowed_test_macro(&canonical) {
            self.report("test code invokes an unallowlisted item macro that cannot be audited");
        }
        visit::visit_item_macro(self, item);
    }

    fn visit_macro(&mut self, mac: &syn::Macro) {
        let canonical = self.path(&mac.path);
        if !is_allowed_test_macro(&canonical) {
            self.report("test code invokes an unallowlisted macro that cannot be audited");
        }
        if canonical.last().is_some_and(|name| name == "include_str")
            && (is_system_path(&mac.tokens.to_string())
                || mac
                    .tokens
                    .to_string()
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .any(|name| self.tainted_bindings.contains(name)))
        {
            self.report("test code includes a protected system path through a macro");
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_path(&mut self, path: &ExprPath) {
        self.check_path(&path.path, None);
        visit::visit_expr_path(self, path);
    }

    fn visit_local(&mut self, local: &syn::Local) {
        if let (syn::Pat::Ident(binding), Some(init)) = (&local.pat, &local.init) {
            if self.has_system_path(&init.expr) {
                self.tainted_bindings.insert(binding.ident.to_string());
            }
            if self.has_boot_order(&init.expr) {
                self.boot_order_bindings.insert(binding.ident.to_string());
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_item_const(&mut self, item: &syn::ItemConst) {
        if self.has_system_path(&item.expr) {
            self.tainted_bindings.insert(item.ident.to_string());
        }
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &syn::ItemStatic) {
        if self.has_system_path(&item.expr) {
            self.tainted_bindings.insert(item.ident.to_string());
        }
        visit::visit_item_static(self, item);
    }

    fn visit_type_path(&mut self, path: &syn::TypePath) {
        self.check_path(&path.path, None);
        visit::visit_type_path(self, path);
    }
}

fn is_allowed_test_macro(path: &[String]) -> bool {
    match path {
        [name] => matches!(
            name.as_str(),
            "assert"
                | "assert_eq"
                | "assert_ne"
                | "concat"
                | "debug_assert"
                | "debug_assert_eq"
                | "debug_assert_ne"
                | "env"
                | "eprintln"
                | "format"
                | "include_str"
                | "matches"
                | "panic"
                | "unreachable"
                | "vec"
        ),
        [prefix, name] if prefix == "serde_json" && name == "json" => true,
        _ => false,
    }
}

fn is_process_command(path: &[String]) -> bool {
    path.windows(3)
        .any(|window| window == ["std", "process", "Command"])
        || path
            .windows(2)
            .any(|window| window == ["process", "Command"])
        || path == ["Command"]
}

fn is_system_bus_path(path: &[String]) -> bool {
    path.windows(4)
        .any(|window| window == ["zbus", "blocking", "connection", "Builder"])
        || path
            .windows(3)
            .any(|window| window == ["zbus", "blocking", "Connection"])
        || path
            .windows(3)
            .any(|window| window == ["zbus", "blocking", "Proxy"])
        || (path.first().is_some_and(|name| name == "zbus")
            && path.iter().any(|name| {
                matches!(
                    name.as_str(),
                    "Connection" | "ConnectionBuilder" | "Builder" | "Proxy"
                )
            }))
        || path
            .first()
            .is_some_and(|name| matches!(name.as_str(), "Connection" | "Builder" | "Proxy"))
}

fn is_libc_system_call(path: &[String]) -> bool {
    let known_boundary = path.last().is_some_and(|name| {
        matches!(
            name.as_str(),
            "reboot"
                | "kexec_load"
                | "syscall"
                | "execve"
                | "execvp"
                | "fork"
                | "vfork"
                | "system"
                | "popen"
                | "mount"
                | "umount"
                | "umount2"
                | "setns"
                | "unshare"
                | "exit"
        )
    });
    known_boundary
        && (path
            .first()
            .is_some_and(|first| first == "libc" || first == "rustix" || first == "nix")
            || path.windows(2).any(|window| window == ["std", "process"])
            // Reboot APIs in crates such as `nix` are often nested below a
            // module path, so the terminal operation is itself denylisted.
            || path.last().is_some_and(|name| name == "reboot"))
}

fn is_libc_path_api(path: &[String]) -> bool {
    path.first().is_some_and(|first| first == "libc")
        && path.last().is_some_and(|name| {
            matches!(
                name.as_str(),
                "open"
                    | "openat"
                    | "creat"
                    | "mkdir"
                    | "mkdirat"
                    | "unlink"
                    | "unlinkat"
                    | "rename"
                    | "renameat"
                    | "stat"
                    | "lstat"
                    | "fstatat"
                    | "access"
                    | "readlink"
                    | "symlink"
                    | "chmod"
                    | "fchmodat"
                    | "chown"
                    | "lchown"
                    | "fchownat"
            )
        })
}

fn is_slint_boundary(path: &[String]) -> bool {
    if path.first().is_some_and(|name| name == "slint") {
        return path.iter().any(|name| {
            matches!(
                name.as_str(),
                "run_event_loop"
                    | "quit_event_loop"
                    | "spin_on"
                    | "invoke_from_event_loop"
                    | "Window"
                    | "ComponentHandle"
            )
        });
    }
    path.iter().any(|name| {
        matches!(
            name.as_str(),
            "AppWindow" | "MainWindow" | "Window" | "ComponentHandle"
        )
    })
}

fn is_production_constructor(path: &[String]) -> bool {
    path.last()
        .is_some_and(|name| matches!(name.as_str(), "with_linux_operation" | "production"))
        || path
            .iter()
            .any(|name| matches!(name.as_str(), "SystemLinuxCalls" | "SystemProcess"))
        || (path.iter().any(|name| name == "LinuxStore")
            && path.last().is_some_and(|name| name == "open"))
        || (path.iter().any(|name| name == "LinuxPlatform")
            && path.last().is_some_and(|name| name == "system"))
        || (path.iter().any(|name| name == "SystemProcess")
            && path
                .last()
                .is_some_and(|name| matches!(name.as_str(), "new" | "default" | "system")))
}

fn is_filesystem_path_api(path: &[String]) -> bool {
    let has_fs = path.windows(2).any(|window| window == ["std", "fs"])
        || path.windows(2).any(|window| window == ["std", "path"])
        || path
            .windows(3)
            .any(|window| window == ["std", "os", "unix"])
        || path.windows(2).any(|window| window == ["rustix", "fs"]);
    has_fs
        && path.last().is_some_and(|name| {
            matches!(
                name.as_str(),
                "read"
                    | "read_to_string"
                    | "write"
                    | "copy"
                    | "rename"
                    | "remove_file"
                    | "remove_dir"
                    | "remove_dir_all"
                    | "create_dir"
                    | "create_dir_all"
                    | "read_dir"
                    | "metadata"
                    | "symlink_metadata"
                    | "canonicalize"
                    | "open"
                    | "openat"
                    | "mkdirat"
                    | "unlinkat"
                    | "symlink"
                    | "Path"
                    | "PathBuf"
                    | "File"
                    | "OpenOptions"
                    | "new"
                    | "from"
            )
        })
}

fn is_unqualified_dangerous_wrapper(path: &[String]) -> bool {
    path.last().is_some_and(|name| {
        matches!(
            name.as_str(),
            "spawn"
                | "exec"
                | "system"
                | "connect"
                | "reboot"
                | "launch"
                | "run"
                | "syscall"
                | "run_event_loop"
                | "quit_event_loop"
                | "spin_on"
                | "invoke_from_event_loop"
        )
    })
}

fn is_system_path(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    [
        "/sys",
        "/proc",
        "/var",
        "/run",
        "/dev",
        "/etc",
        "/usr",
        "/boot",
        "efivarfs",
        "system_bus_socket",
    ]
    .iter()
    .any(|prefix| {
        normalized == *prefix
            || normalized.starts_with(&format!("{prefix}/"))
            || normalized.contains(&format!("{prefix}/"))
    })
}

#[cfg(test)]
fn audit_source(source: &str, label: &str) -> Result<(), String> {
    let file = syn::parse_file(source).map_err(|error| error.to_string())?;
    let root = Path::new(".")
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let path = PathBuf::from(label);
    let mut state = AuditState::default();
    let mut parsed = HashMap::new();
    parsed.insert(path.clone(), file);
    state.dangerous_functions = collect_dangerous_functions(&parsed);
    let file = parsed.get(&path).expect("just inserted source");
    audit_test_items(
        &file.items,
        &path,
        &root,
        &AliasMap::new(),
        &parsed,
        &mut state,
    );
    if state.issues.is_empty() {
        Ok(())
    } else {
        Err(state
            .issues
            .into_iter()
            .map(|issue| issue.message)
            .collect::<Vec<_>>()
            .join("; "))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cfg_test_attribute_is_detected() {
        let file = syn::parse_file("#[cfg(test)] mod tests { fn x() {} }").unwrap();
        let syn::Item::Mod(module) = &file.items[0] else {
            panic!()
        };
        assert!(super::has_test_cfg(&module.attrs));
    }

    #[test]
    fn nested_cfg_and_cfg_attr_test_attributes_are_detected() {
        let file = syn::parse_file(
            "#[cfg(all(feature = \"fixture\", any(test, feature = \"other\")))] mod one {}\n#[cfg_attr(test, allow(dead_code))] mod two {}",
        )
        .unwrap();
        for item in &file.items {
            let syn::Item::Mod(module) = item else {
                panic!()
            };
            assert!(super::has_test_cfg(&module.attrs));
        }
    }

    #[test]
    fn aliased_process_and_nested_cfg_sources_are_rejected() {
        let source = r#"
            use std::{process as p, process::Command as Spawn};
            #[cfg(any(test, feature = "fixture"))]
            mod first {
                use super::*;
                fn evil() { let _ = Spawn::new("/usr/bin/pkexec").status(); }
            }
            #[cfg(test)]
            mod second { fn evil() { let _ = p::Command::new("helper").output(); } }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn reexported_aliases_do_not_hide_process_construction() {
        let source = r#"
            extern crate std as standard;
            use std::process::Command as C;
            use C as Spawn;
            fn evil() {
                let _ = Spawn::new("helper");
                let _ = standard::process::Command::new("helper");
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn indirect_wrapper_with_an_innocuous_name_is_rejected() {
        let source = r#"
            fn do_the_thing() {
                std::process::Command::new("helper").status().unwrap();
            }
            #[cfg(test)]
            mod tests {
                fn call_wrapper() { super::do_the_thing(); }
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn unallowlisted_macro_is_rejected_in_test_code() {
        let source = r#"
            #[cfg(test)]
            mod tests {
                fn generated() { hidden_boundary!(); }
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn dto_strings_and_fake_reboot_methods_are_accepted() {
        let source = r#"
            trait Fake { fn reboot(&mut self); }
            struct Stub;
            impl Fake for Stub { fn reboot(&mut self) {} }
            fn expected() -> &'static str { "/usr/bin/pkexec" }
            #[cfg(test)] mod tests { fn expected_path() -> &'static str { "/sys/firmware/efi/efivars" } }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_ok());
    }

    #[test]
    fn local_imports_and_indirect_system_paths_are_rejected() {
        let source = r#"
            fn evil() {
                use std::fs as files;
                use std::process::Command as Spawn;
                let root = "/sys";
                let path = format!("{root}/firmware/efi/efivars");
                let _ = files::read(path);
                let _ = Spawn::new("helper").status();
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn split_system_path_taint_reaches_the_filesystem_call() {
        let source = r#"
            fn evil() {
                use std::fs as files;
                let root = "/sys";
                let path = format!("{root}/firmware/efi/efivars");
                let _ = files::read(path);
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn nested_expression_system_path_taint_is_rejected() {
        let source = r#"
            fn evil() {
                use std::fs as files;
                let path = if cfg!(test) { "/sys" } else { "/tmp" };
                let _ = files::read(path);
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn every_system_boundary_alias_is_rejected() {
        let source = r#"
            use libc as c;
            use zbus::blocking::connection::Builder as Bus;
            use slint::run_event_loop as loop_forever;
            use boothop_platform::linux::LinuxPlatform as Host;
            fn evil() {
                let _ = Bus::address("unix:path=/run/dbus/system_bus_socket");
                let _ = c::syscall(0);
                let _ = loop_forever();
                let _ = Host::system(&mut fake_store());
            }
            fn fake_store() -> FakeStore { FakeStore }
            struct FakeStore;
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }
}
