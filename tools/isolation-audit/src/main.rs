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
    Attribute, BinOp, Expr, ExprAssign, ExprBinary, ExprCall, ExprLit, ExprMacro, ExprMethodCall,
    ExprPath, ExprReturn, File, ImplItem, Item, ItemImpl, ItemMod, ItemTrait, Lit, Meta, Pat, Stmt,
    TraitItem, Type, UseTree,
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
    tainted_functions: HashSet<String>,
    parameter_boundary_functions: HashSet<String>,
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
    state.tainted_functions = collect_tainted_functions(&parsed);
    state.parameter_boundary_functions =
        collect_parameter_boundary_functions(&parsed, &state.tainted_functions);
    state.dangerous_functions = collect_dangerous_functions(
        &parsed,
        &state.tainted_functions,
        &state.parameter_boundary_functions,
    );
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

#[derive(Clone)]
struct FunctionDef {
    name: String,
    source_path: PathBuf,
    block: syn::Block,
    aliases: AliasMap,
    parameters: HashSet<String>,
    method_owner: Option<String>,
    test_only: bool,
}

fn type_name(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else { return None };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn function_key(function: &FunctionDef) -> String {
    function.method_owner.as_ref().map_or_else(
        || format!("fn::{}", function.name),
        |owner| format!("method::{owner}::{}", function.name),
    )
}

fn collect_function_defs(parsed: &HashMap<PathBuf, File>) -> Vec<FunctionDef> {
    fn collect_items(
        items: &[Item],
        source_path: &Path,
        inherited: &AliasMap,
        test_only: bool,
        output: &mut Vec<FunctionDef>,
    ) {
        let mut aliases = inherited.clone();
        collect_aliases(items, &mut aliases);
        for item in items {
            match item {
                Item::Fn(function) => output.push(FunctionDef {
                    name: function.sig.ident.to_string(),
                    source_path: source_path.to_path_buf(),
                    block: (*function.block).clone(),
                    aliases: aliases.clone(),
                    parameters: signature_parameters(&function.sig),
                    method_owner: None,
                    test_only,
                }),
                Item::Impl(ItemImpl { self_ty, items, .. }) => {
                    let method_owner = type_name(self_ty);
                    for item in items {
                        let ImplItem::Fn(function) = item else {
                            continue;
                        };
                        output.push(FunctionDef {
                            name: function.sig.ident.to_string(),
                            source_path: source_path.to_path_buf(),
                            block: function.block.clone(),
                            aliases: aliases.clone(),
                            parameters: signature_parameters(&function.sig),
                            method_owner: method_owner.clone(),
                            test_only,
                        });
                    }
                }
                Item::Trait(ItemTrait { ident, items, .. }) => {
                    for item in items {
                        let TraitItem::Fn(function) = item else {
                            continue;
                        };
                        let Some(block) = &function.default else {
                            continue;
                        };
                        output.push(FunctionDef {
                            name: function.sig.ident.to_string(),
                            source_path: source_path.to_path_buf(),
                            block: block.clone(),
                            aliases: aliases.clone(),
                            parameters: signature_parameters(&function.sig),
                            method_owner: Some(ident.to_string()),
                            test_only,
                        });
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        collect_items(
                            nested,
                            source_path,
                            &aliases,
                            test_only || has_test_cfg(&module.attrs),
                            output,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    let mut output = Vec::new();
    for (path, file) in parsed {
        let test_only = path.components().any(|part| part.as_os_str() == "tests");
        collect_items(&file.items, path, &AliasMap::new(), test_only, &mut output);
    }
    output
}

struct TraitImplDef {
    trait_name: String,
    owner: String,
    methods: HashSet<String>,
}

fn collect_trait_impls(parsed: &HashMap<PathBuf, File>) -> Vec<TraitImplDef> {
    fn collect_items(items: &[Item], output: &mut Vec<TraitImplDef>) {
        for item in items {
            match item {
                Item::Impl(ItemImpl {
                    self_ty,
                    trait_: Some((_, path, _)),
                    items,
                    ..
                }) => {
                    let Some(owner) = type_name(self_ty) else {
                        continue;
                    };
                    let Some(trait_name) = path.segments.last() else {
                        continue;
                    };
                    let methods = items
                        .iter()
                        .filter_map(|item| match item {
                            ImplItem::Fn(function) => Some(function.sig.ident.to_string()),
                            _ => None,
                        })
                        .collect();
                    output.push(TraitImplDef {
                        trait_name: trait_name.ident.to_string(),
                        owner,
                        methods,
                    });
                }
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        collect_items(nested, output);
                    }
                }
                _ => {}
            }
        }
    }

    let mut output = Vec::new();
    for file in parsed.values() {
        collect_items(&file.items, &mut output);
    }
    output
}

fn signature_parameters(signature: &syn::Signature) -> HashSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(typed) => simple_pattern_name(&typed.pat),
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn simple_pattern_name(pattern: &Pat) -> Option<String> {
    match pattern {
        Pat::Ident(binding) => Some(binding.ident.to_string()),
        Pat::Type(typed) => simple_pattern_name(&typed.pat),
        Pat::Reference(reference) => simple_pattern_name(&reference.pat),
        _ => None,
    }
}

fn audit_function_body(
    function: &FunctionDef,
    dangerous_functions: &HashSet<String>,
    tainted_functions: &HashSet<String>,
    parameter_boundary_functions: &HashSet<String>,
) -> (bool, bool, bool) {
    let mut issues = Vec::new();
    let mut visitor = ExprAudit::new(
        &function.aliases,
        function.source_path.as_path(),
        &mut issues,
        dangerous_functions,
        tainted_functions,
        parameter_boundary_functions,
        &function.parameters,
        false,
        false,
    );
    visitor.visit_block(&function.block);
    let return_tainted = visitor.return_tainted;
    let parameter_boundary = visitor.parameter_boundary;
    drop(visitor);
    (!issues.is_empty(), return_tainted, parameter_boundary)
}

fn collect_tainted_functions(parsed: &HashMap<PathBuf, File>) -> HashSet<String> {
    let functions = collect_function_defs(parsed);
    let mut tainted = HashSet::new();
    loop {
        let mut additions = HashSet::new();
        for function in &functions {
            if function.test_only {
                continue;
            }
            let (_, returns_tainted, _) =
                audit_function_body(function, &HashSet::new(), &tainted, &HashSet::new());
            if returns_tainted {
                additions.insert(function_key(function));
            }
        }
        let previous = tainted.len();
        tainted.extend(additions);
        if tainted.len() == previous {
            return tainted;
        }
    }
}

fn collect_parameter_boundary_functions(
    parsed: &HashMap<PathBuf, File>,
    tainted_functions: &HashSet<String>,
) -> HashSet<String> {
    let functions = collect_function_defs(parsed);
    let mut parameter_boundaries = HashSet::new();
    for function in &functions {
        if function.test_only {
            continue;
        }
        let (_, _, uses_parameter) = audit_function_body(
            function,
            &HashSet::new(),
            tainted_functions,
            &parameter_boundaries,
        );
        if uses_parameter {
            parameter_boundaries.insert(function_key(function));
        }
    }
    parameter_boundaries
}

fn collect_dangerous_functions(
    parsed: &HashMap<PathBuf, File>,
    tainted_functions: &HashSet<String>,
    parameter_boundary_functions: &HashSet<String>,
) -> HashSet<String> {
    let functions = collect_function_defs(parsed);
    let trait_impls = collect_trait_impls(parsed);
    let mut dangerous = HashSet::new();
    loop {
        let known = dangerous.clone();
        let mut additions = HashSet::new();
        for function in &functions {
            if function.test_only {
                continue;
            }
            let (is_dangerous, _, _) = audit_function_body(
                function,
                &known,
                tainted_functions,
                parameter_boundary_functions,
            );
            if is_dangerous {
                additions.insert(function_key(function));
            }
        }
        let previous = dangerous.len();
        dangerous.extend(additions);
        for implementation in &trait_impls {
            for default_key in dangerous.clone() {
                let Some(method) =
                    default_key.strip_prefix(&format!("method::{}::", implementation.trait_name))
                else {
                    continue;
                };
                if !implementation.methods.contains(method) {
                    dangerous.insert(format!("method::{}::{method}", implementation.owner));
                }
            }
        }
        if dangerous.len() == previous {
            return dangerous;
        }
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
    let no_parameters = HashSet::new();
    for item in items {
        // Child modules are visited below with a fresh lexical alias scope;
        // visiting them here would leak their imports into sibling modules.
        if !matches!(item, Item::Mod(_)) {
            let mut visitor = ExprAudit::new(
                &aliases,
                source_path,
                &mut state.issues,
                &state.dangerous_functions,
                &state.tainted_functions,
                &state.parameter_boundary_functions,
                &no_parameters,
                true,
                true,
            );
            visit::Visit::visit_item(&mut visitor, item);
        }
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

fn resolve_scoped_path(path: &syn::Path, scopes: &[AliasMap]) -> Option<Vec<String>> {
    let first = path.segments.first()?.ident.to_string();
    let mut result = scopes
        .iter()
        .rev()
        .find_map(|scope| scope.get(&first).cloned())
        .unwrap_or_else(|| vec![first]);
    let mut expanded = HashSet::new();
    while let Some(head) = result.first().cloned() {
        if !expanded.insert(head.clone()) {
            break;
        }
        let Some(replacement) = scopes.iter().rev().find_map(|scope| scope.get(&head)) else {
            break;
        };
        let mut next = replacement.clone();
        next.extend(result.into_iter().skip(1));
        result = next;
    }
    result.extend(
        path.segments
            .iter()
            .skip(1)
            .map(|segment| segment.ident.to_string()),
    );
    Some(result)
}

fn split_macro_tokens(tokens: proc_macro2::TokenStream) -> Vec<proc_macro2::TokenStream> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut parts = vec![proc_macro2::TokenStream::new()];
    for token in tokens {
        if let proc_macro2::TokenTree::Punct(punct) = &token
            && punct.as_char() == ','
            && punct.spacing() == proc_macro2::Spacing::Alone
        {
            parts.push(proc_macro2::TokenStream::new());
        } else if let Some(part) = parts.last_mut() {
            part.extend(std::iter::once(token));
        }
    }
    if parts.last().is_some_and(proc_macro2::TokenStream::is_empty) {
        parts.pop();
    }
    parts
}

fn split_macro_semicolon(tokens: proc_macro2::TokenStream) -> Vec<proc_macro2::TokenStream> {
    let mut parts = vec![proc_macro2::TokenStream::new()];
    for token in tokens {
        if let proc_macro2::TokenTree::Punct(punct) = &token
            && punct.as_char() == ';'
            && punct.spacing() == proc_macro2::Spacing::Alone
        {
            parts.push(proc_macro2::TokenStream::new());
        } else if let Some(part) = parts.last_mut() {
            part.extend(std::iter::once(token));
        }
    }
    if parts.last().is_some_and(proc_macro2::TokenStream::is_empty) {
        parts.pop();
    }
    parts
}

fn split_macro_colon(tokens: proc_macro2::TokenStream) -> Vec<proc_macro2::TokenStream> {
    let mut parts = vec![proc_macro2::TokenStream::new()];
    let mut previous_colon_was_joint = false;
    for token in tokens {
        let current_colon_is_joint = matches!(&token, proc_macro2::TokenTree::Punct(punct)
            if punct.as_char() == ':' && punct.spacing() == proc_macro2::Spacing::Joint);
        let separator = matches!(&token, proc_macro2::TokenTree::Punct(punct)
            if punct.as_char() == ':'
                && punct.spacing() == proc_macro2::Spacing::Alone
                && !previous_colon_was_joint);
        if separator {
            parts.push(proc_macro2::TokenStream::new());
        } else if let Some(part) = parts.last_mut() {
            part.extend(std::iter::once(token));
        }
        previous_colon_was_joint = current_colon_is_joint;
    }
    parts
}

fn parse_json_macro_exprs(mac: &syn::Macro) -> Result<Vec<Expr>, ()> {
    fn collect(stream: proc_macro2::TokenStream, output: &mut Vec<Expr>) -> Result<(), ()> {
        for part in split_macro_tokens(stream) {
            if part.is_empty() {
                continue;
            }
            let colon = split_macro_colon(part.clone());
            let candidate = colon.last().cloned().ok_or(())?;
            if colon.len() > 1 {
                if collect(candidate.clone(), output).is_err() {
                    return Err(());
                }
                continue;
            }
            if let Ok(expr) = syn::parse2::<Expr>(candidate.clone()) {
                output.push(expr);
                continue;
            }
            let mut found_group = false;
            for token in candidate.clone() {
                if let proc_macro2::TokenTree::Group(group) = token {
                    found_group = true;
                    collect(group.stream(), output)?;
                }
            }
            if !found_group {
                return Err(());
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    collect(mac.tokens.clone(), &mut output)?;
    Ok(output)
}

fn parse_macro_exprs(mac: &syn::Macro) -> Result<Vec<Expr>, ()> {
    let name = mac
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string());
    if name.as_deref() == Some("json") {
        return parse_json_macro_exprs(mac);
    }
    let mut expressions = Vec::new();
    for part in split_macro_tokens(mac.tokens.clone()) {
        let semicolon_parts = split_macro_semicolon(part);
        if name.as_deref() == Some("matches") {
            // `matches!` has a pattern (not an expression) after the first
            // comma. Its expression is the only part relevant to boundary
            // execution; the pattern is syntax-checked by syn itself.
            if let Some(first) = semicolon_parts.first()
                && let Ok(expr) = syn::parse2::<Expr>(first.clone())
            {
                expressions.push(expr);
            }
            break;
        }
        for segment in semicolon_parts {
            if segment.is_empty() {
                return Err(());
            }
            expressions.push(syn::parse2::<Expr>(segment).map_err(|_| ())?);
        }
    }
    Ok(expressions)
}

fn macro_literal_concat(mac: &syn::Macro) -> Option<String> {
    if mac.path.segments.last()?.ident != "concat" {
        return None;
    }
    let exprs = parse_macro_exprs(mac).ok()?;
    let mut output = String::new();
    for expr in exprs {
        let Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        }) = expr
        else {
            return None;
        };
        output.push_str(&value.value());
    }
    Some(output)
}

struct PathTaint<'a> {
    tainted_bindings: &'a HashSet<String>,
    tainted_functions: &'a HashSet<String>,
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

    fn visit_expr_call(&mut self, expr: &ExprCall) {
        if let Expr::Path(path) = &*expr.func
            && path.path.segments.last().is_some_and(|segment| {
                self.tainted_functions
                    .contains(&format!("fn::{}", segment.ident))
            })
        {
            self.found = true;
        }
        visit::visit_expr_call(self, expr);
    }

    fn visit_expr_macro(&mut self, expr: &ExprMacro) {
        let text = expr.mac.tokens.to_string();
        self.found |= is_system_path(&text)
            || text
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|name| self.tainted_bindings.contains(name));
        self.found |= macro_literal_concat(&expr.mac).is_some_and(|value| is_system_path(&value));
        if let Ok(arguments) = parse_macro_exprs(&expr.mac) {
            for argument in arguments {
                self.visit_expr(&argument);
            }
        }
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
        self.found |= macro_literal_concat(&expr.mac)
            .is_some_and(|value| value.contains("BootOrder") || value.contains("BootCurrent"));
        if let Ok(arguments) = parse_macro_exprs(&expr.mac) {
            for argument in arguments {
                self.visit_expr(&argument);
            }
        }
    }
}

struct ExprAudit<'a> {
    alias_scopes: Vec<AliasMap>,
    source_path: &'a Path,
    issues: &'a mut Vec<Issue>,
    dangerous_functions: &'a HashSet<String>,
    tainted_functions: &'a HashSet<String>,
    parameter_boundary_functions: &'a HashSet<String>,
    parameters: &'a HashSet<String>,
    tainted_bindings: HashSet<String>,
    boot_order_bindings: HashSet<String>,
    receiver_types: HashMap<String, String>,
    return_tainted: bool,
    parameter_boundary: bool,
    report_parameter_boundary: bool,
    report_unresolved_wrappers: bool,
}

impl ExprAudit<'_> {
    #[allow(clippy::too_many_arguments)]
    fn new<'a>(
        aliases: &AliasMap,
        source_path: &'a Path,
        issues: &'a mut Vec<Issue>,
        dangerous_functions: &'a HashSet<String>,
        tainted_functions: &'a HashSet<String>,
        parameter_boundary_functions: &'a HashSet<String>,
        parameters: &'a HashSet<String>,
        report_parameter_boundary: bool,
        report_unresolved_wrappers: bool,
    ) -> ExprAudit<'a> {
        ExprAudit {
            alias_scopes: vec![aliases.clone()],
            source_path,
            issues,
            dangerous_functions,
            tainted_functions,
            parameter_boundary_functions,
            parameters,
            tainted_bindings: HashSet::new(),
            boot_order_bindings: HashSet::new(),
            receiver_types: HashMap::new(),
            return_tainted: false,
            parameter_boundary: false,
            report_parameter_boundary,
            report_unresolved_wrappers,
        }
    }

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
        resolve_scoped_path(path, &self.alias_scopes).unwrap_or_default()
    }

    fn check_path(&mut self, path: &syn::Path, args: Option<&[Expr]>, check_wrappers: bool) {
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
        if check_wrappers
            && canonical
                .last()
                .is_some_and(|name| self.dangerous_functions.contains(&format!("fn::{name}")))
        {
            self.report("test code calls a wrapper whose body crosses a protected system boundary");
            return;
        }
        if is_filesystem_path_api(&canonical)
            && args.is_some_and(|args| {
                args.iter()
                    .any(|arg| self.has_system_path(arg) || self.has_parameter(arg))
            })
        {
            let parameter = args.is_some_and(|args| args.iter().any(|arg| self.has_parameter(arg)));
            if parameter {
                self.parameter_boundary = true;
            }
            if !parameter || self.report_parameter_boundary {
                self.report("test code accesses a protected system path through a filesystem API");
            }
        }
        if self.parameter_boundary_functions.iter().any(|name| {
            canonical
                .last()
                .is_some_and(|last| name == &format!("fn::{last}"))
        }) && args.is_some_and(|args| args.iter().any(|arg| self.has_system_path(arg)))
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
            tainted_functions: self.tainted_functions,
            found: false,
        };
        visitor.visit_expr(expr);
        visitor.found
    }

    fn has_parameter(&self, expr: &Expr) -> bool {
        struct ParameterUse<'a> {
            parameters: &'a HashSet<String>,
            found: bool,
        }
        impl Visit<'_> for ParameterUse<'_> {
            fn visit_expr_path(&mut self, path: &ExprPath) {
                if path
                    .path
                    .segments
                    .first()
                    .is_some_and(|segment| self.parameters.contains(&segment.ident.to_string()))
                {
                    self.found = true;
                }
                visit::visit_expr_path(self, path);
            }
        }
        let mut visitor = ParameterUse {
            parameters: self.parameters,
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

    fn current_aliases(&mut self) -> &mut AliasMap {
        self.alias_scopes
            .last_mut()
            .expect("ExprAudit always has a module alias scope")
    }

    fn receiver_type(&self, expression: &Expr) -> Option<String> {
        match expression {
            Expr::Path(path) => {
                let first = path.path.segments.first()?.ident.to_string();
                let last = path.path.segments.last()?.ident.to_string();
                self.receiver_types
                    .get(&first)
                    .cloned()
                    .or_else(|| self.receiver_types.get(&last).cloned())
                    .or_else(|| {
                        last.chars()
                            .next()
                            .filter(|character| character.is_uppercase())
                            .map(|_| last)
                    })
            }
            Expr::Reference(reference) => self.receiver_type(&reference.expr),
            Expr::Paren(paren) => self.receiver_type(&paren.expr),
            Expr::Group(group) => self.receiver_type(&group.expr),
            Expr::Struct(structure) => type_name(&Type::Path(syn::TypePath {
                qself: None,
                path: structure.path.clone(),
            })),
            _ => None,
        }
    }

    fn mark_pattern(&mut self, pattern: &Pat, tainted: bool, boot_order: bool) {
        match pattern {
            Pat::Ident(binding) => {
                if tainted {
                    self.tainted_bindings.insert(binding.ident.to_string());
                }
                if boot_order {
                    self.boot_order_bindings.insert(binding.ident.to_string());
                }
                if let Some((_, subpattern)) = &binding.subpat {
                    self.mark_pattern(subpattern, tainted, boot_order);
                }
            }
            Pat::Type(typed) => self.mark_pattern(&typed.pat, tainted, boot_order),
            Pat::Reference(reference) => self.mark_pattern(&reference.pat, tainted, boot_order),
            Pat::Paren(paren) => self.mark_pattern(&paren.pat, tainted, boot_order),
            Pat::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.mark_pattern(element, tainted, boot_order);
                }
            }
            Pat::TupleStruct(tuple) => {
                for element in &tuple.elems {
                    self.mark_pattern(element, tainted, boot_order);
                }
            }
            Pat::Struct(structure) => {
                for field in &structure.fields {
                    self.mark_pattern(&field.pat, tainted, boot_order);
                }
            }
            Pat::Slice(slice) => {
                for element in &slice.elems {
                    self.mark_pattern(element, tainted, boot_order);
                }
            }
            _ => {}
        }
    }

    fn mark_assignment_target(&mut self, expression: &Expr, tainted: bool, boot_order: bool) {
        match expression {
            Expr::Path(path) => {
                if let Some(binding) = path.path.segments.last() {
                    if tainted {
                        self.tainted_bindings.insert(binding.ident.to_string());
                    }
                    if boot_order {
                        self.boot_order_bindings.insert(binding.ident.to_string());
                    }
                }
            }
            Expr::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.mark_assignment_target(element, tainted, boot_order);
                }
            }
            Expr::Array(array) => {
                for element in &array.elems {
                    self.mark_assignment_target(element, tainted, boot_order);
                }
            }
            Expr::Paren(paren) => self.mark_assignment_target(&paren.expr, tainted, boot_order),
            Expr::Group(group) => self.mark_assignment_target(&group.expr, tainted, boot_order),
            _ => {}
        }
    }

    fn inspect_macro(&mut self, mac: &syn::Macro) {
        let canonical = self.path(&mac.path);
        if !is_allowed_test_macro(&canonical) {
            self.report("test code invokes an unallowlisted macro that cannot be audited");
            return;
        }
        if canonical.last().is_some_and(|name| name == "include_str")
            && is_system_path(&mac.tokens.to_string())
        {
            self.report("test code includes a protected system path through a macro");
        }
        let Ok(arguments) = parse_macro_exprs(mac) else {
            self.report("allowlisted macro cannot be parsed for boundary audit");
            return;
        };
        for argument in arguments {
            self.visit_expr(&argument);
        }
    }
}

impl Visit<'_> for ExprAudit<'_> {
    fn visit_expr_call(&mut self, call: &ExprCall) {
        if let Expr::Path(path) = &*call.func {
            let args = call.args.iter().cloned().collect::<Vec<_>>();
            self.check_path(&path.path, Some(&args), true);
            if self.report_unresolved_wrappers
                && is_unqualified_dangerous_wrapper(&self.path(&path.path))
            {
                self.report("test code calls an unresolved process/system wrapper");
            }
            if is_boot_next_write_api(self.path(&path.path).last().map(String::as_str))
                && args.iter().any(|arg| self.has_boot_order(arg))
            {
                self.report("fake write assertion may target BootNext only");
            }
            let method_owner = path
                .qself
                .as_ref()
                .and_then(|qself| type_name(&qself.ty))
                .or_else(|| {
                    let canonical = self.path(&path.path);
                    (canonical.len() >= 2).then(|| canonical[canonical.len() - 2].clone())
                });
            if method_owner.is_some_and(|owner| {
                self.dangerous_functions.contains(&format!(
                    "method::{owner}::{}",
                    path.path.segments.last().unwrap().ident
                ))
            }) {
                self.report(
                    "test code calls a wrapper whose body crosses a protected system boundary",
                );
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
        if is_boot_next_write_api(Some(&call.method.to_string()))
            && call.args.iter().any(|arg| self.has_boot_order(arg))
        {
            self.report("fake write assertion may target BootNext only");
        }
        if self.receiver_type(&call.receiver).is_some_and(|owner| {
            self.dangerous_functions
                .contains(&format!("method::{owner}::{}", call.method))
        }) {
            self.report(format!(
                "test code calls a wrapper whose body crosses a protected system boundary: {}",
                call.method
            ));
        }
        if let Expr::Path(path) = &*call.receiver {
            let canonical = self.path(&path.path);
            let args = call.args.iter().cloned().collect::<Vec<_>>();
            if is_filesystem_path_api(&canonical)
                && args.iter().any(|arg| self.has_system_path(arg))
            {
                self.report(format!(
                    "test code accesses a protected system path through a filesystem API: {}",
                    canonical.join("::")
                ));
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
        self.inspect_macro(&expr.mac);
    }

    fn visit_item_macro(&mut self, item: &syn::ItemMacro) {
        self.inspect_macro(&item.mac);
    }

    fn visit_macro(&mut self, mac: &syn::Macro) {
        self.inspect_macro(mac);
    }

    fn visit_item_use(&mut self, item: &syn::ItemUse) {
        collect_use_tree(None, &item.tree, self.current_aliases());
    }

    fn visit_item_type(&mut self, item: &syn::ItemType) {
        if let Type::Path(type_path) = &*item.ty
            && let Some(path) = resolve_scoped_path(&type_path.path, &self.alias_scopes)
        {
            self.current_aliases().insert(item.ident.to_string(), path);
        }
        visit::visit_item_type(self, item);
    }

    fn visit_block(&mut self, block: &syn::Block) {
        self.alias_scopes.push(AliasMap::new());
        visit::visit_block(self, block);
        self.alias_scopes.pop();
        if let Some(Stmt::Expr(expression, None)) = block.stmts.last()
            && self.has_system_path(expression)
        {
            self.return_tainted = true;
        }
    }

    fn visit_expr_return(&mut self, expression: &ExprReturn) {
        if expression
            .expr
            .as_deref()
            .is_some_and(|expr| self.has_system_path(expr))
        {
            self.return_tainted = true;
        }
        visit::visit_expr_return(self, expression);
    }

    fn visit_expr_assign(&mut self, expression: &ExprAssign) {
        let system_path = self.has_system_path(&expression.right);
        let boot_order = self.has_boot_order(&expression.right);
        self.mark_assignment_target(&expression.left, system_path, boot_order);
        visit::visit_expr_assign(self, expression);
    }

    fn visit_expr_binary(&mut self, expression: &ExprBinary) {
        if matches!(expression.op, BinOp::AddAssign(_))
            && let Expr::Path(path) = &*expression.left
        {
            if self.has_system_path(&expression.right)
                && let Some(binding) = path.path.segments.last()
            {
                self.tainted_bindings.insert(binding.ident.to_string());
            }
            if self.has_boot_order(&expression.right)
                && let Some(binding) = path.path.segments.last()
            {
                self.boot_order_bindings.insert(binding.ident.to_string());
            }
        }
        visit::visit_expr_binary(self, expression);
    }

    fn visit_expr_path(&mut self, path: &ExprPath) {
        self.check_path(&path.path, None, false);
        visit::visit_expr_path(self, path);
    }

    fn visit_local(&mut self, local: &syn::Local) {
        if let Pat::Ident(binding) = &local.pat
            && let Some(init) = &local.init
            && let Some(owner) = self.receiver_type(&init.expr)
        {
            self.receiver_types.insert(binding.ident.to_string(), owner);
        }
        if let Pat::Type(typed) = &local.pat
            && let Pat::Ident(binding) = &*typed.pat
            && let Some(owner) = type_name(&typed.ty)
        {
            self.receiver_types.insert(binding.ident.to_string(), owner);
        }
        if let Some(init) = &local.init {
            self.mark_pattern(
                &local.pat,
                self.has_system_path(&init.expr),
                self.has_boot_order(&init.expr),
            );
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
        self.check_path(&path.path, None, false);
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
            || path.windows(2).any(|window| window == ["std", "process"]))
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

fn is_boot_next_write_api(name: Option<&str>) -> bool {
    let Some(name) = name else { return false };
    let name = name.to_ascii_lowercase();
    name == "write_next"
        || name.contains("write_next")
        || name.contains("write_boot_next")
        || name.contains("set_boot_next")
        || name.contains("write_boot_variable")
        || name.contains("set_boot_variable")
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
    state.tainted_functions = collect_tainted_functions(&parsed);
    state.parameter_boundary_functions =
        collect_parameter_boundary_functions(&parsed, &state.tainted_functions);
    state.dangerous_functions = collect_dangerous_functions(
        &parsed,
        &state.tainted_functions,
        &state.parameter_boundary_functions,
    );
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

    #[test]
    fn allowlisted_macros_are_recursively_audited() {
        let source = r#"
            #[cfg(test)]
            mod tests {
                fn evil() {
                    assert!(format!("{:?}", std::process::Command::new("helper")).is_empty());
                    let _ = vec![zbus::blocking::Connection::session()];
                    assert_eq!(concat!("re", "boot"), libc::reboot(0));
                }
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn impl_trait_and_ufcs_methods_propagate_boundary_summaries() {
        let source = r#"
            struct Runner;
            impl Runner {
                fn hidden(&self) {
                    std::process::Command::new("helper").status().unwrap();
                }
            }
            trait Bus {
                fn hidden_bus(&self) {
                    let _ = zbus::blocking::Connection::session();
                }
            }
            struct Device;
            impl Bus for Device {}
            #[cfg(test)]
            mod tests {
                fn invoke() {
                    let runner = super::Runner;
                    runner.hidden();
                    let device = super::Device;
                    device.hidden_bus();
                    <super::Device as super::Bus>::hidden_bus(&device);
                }
            }
        "#;
        let file = syn::parse_file(source).unwrap();
        let path = std::path::PathBuf::from("fixture.rs");
        let mut parsed = std::collections::HashMap::new();
        parsed.insert(path.clone(), file);
        let tainted = super::collect_tainted_functions(&parsed);
        let parameter_boundaries = super::collect_parameter_boundary_functions(&parsed, &tainted);
        let dangerous =
            super::collect_dangerous_functions(&parsed, &tainted, &parameter_boundaries);
        assert!(dangerous.contains("method::Runner::hidden"));
        assert!(dangerous.contains("method::Bus::hidden_bus"));
        assert!(dangerous.contains("method::Device::hidden_bus"));

        let root = std::path::Path::new(".").canonicalize().unwrap();
        let file = parsed.get(&path).unwrap();
        let mut state = super::AuditState {
            dangerous_functions: dangerous,
            tainted_functions: tainted,
            parameter_boundary_functions: parameter_boundaries,
            ..Default::default()
        };
        super::audit_cfg_modules(
            &file.items,
            &path,
            &root,
            &super::AliasMap::new(),
            &parsed,
            &mut state,
        );
        assert!(!state.issues.is_empty());
    }

    #[test]
    fn aliases_are_lexically_scoped_and_later_safe_aliases_cannot_hide_danger() {
        let source = r#"
            fn dangerous() {
                use std::process::Command as C;
                let _ = C::new("helper");
            }
            fn safe() {
                use safe::Thing as C;
                let _ = C::new();
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn unrelated_function_alias_does_not_poison_safe_function() {
        let source = r#"
            fn safe() {
                use safe::Thing as C;
                let _ = C::new();
            }
            fn unrelated() {
                use std::process::Command as C;
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_ok());
    }

    #[test]
    fn taint_tracks_updates_destructuring_returns_and_cross_function_parameters() {
        let source = r#"
            fn source_path() -> &'static str { concat!("/", "sys") }
            fn read_path(path: &str) { let _ = std::fs::read(path); }
            fn evil() {
                let mut path = "/tmp";
                path = source_path();
                let (first, _second) = (path, "/tmp");
                read_path(first);
            }
        "#;
        let result = super::audit_source(source, "fixture.rs");
        assert!(result.is_err());
    }

    #[test]
    fn tuple_assignment_updates_path_taint() {
        let source = r#"
            fn source_path() -> &'static str { concat!("/", "sys") }
            fn read_path(path: &str) { let _ = std::fs::read(path); }
            fn evil() {
                let mut assigned = "/tmp";
                let mut untouched = "/tmp";
                (assigned, untouched) = (source_path(), untouched);
                read_path(assigned);
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }

    #[test]
    fn boot_order_concat_rejects_boot_next_write_api_variants() {
        let source = r#"
            struct Fake;
            impl Fake {
                fn write_boot_next(&mut self, _: &str) {}
            }
            fn evil(fake: &mut Fake) {
                let target = concat!("Boot", "Order");
                fake.write_boot_next(target);
            }
        "#;
        assert!(super::audit_source(source, "fixture.rs").is_err());
    }
}
