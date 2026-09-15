#[derive(Clone, Debug)]
pub struct Probe {
    pub systemd_version: String,
    /// Authority daemon version only; says nothing about a GUI authentication agent.
    pub polkit_version: String,
    pub effective_uid: u32,
    pub introspection: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Success,
    ExplicitDenial,
    DisconnectedAfterSend,
    TimedOutAfterSend,
    NotSent,
}
use boothop_core::{Error, PlatformOperation};

pub(crate) fn validate_probe(probe: &Probe) -> Result<(), Error> {
    if probe.effective_uid != 0 {
        return Err(super::firmware::io(PlatformOperation::Reboot, 1));
    }
    fn version(text: &str) -> Option<u32> {
        text.split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    }
    if !version(&probe.systemd_version).is_some_and(|v| v >= 255)
        || !version(&probe.polkit_version).is_some_and(|v| v >= 124)
    {
        return Err(Error::UnsupportedFormat);
    }
    if probe.introspection.len() > 1_048_576 {
        return Err(Error::ResourceLimit);
    }
    // Standard D-Bus introspection has a DOCTYPE. No resolver is installed, so parsing
    // never fetches external entities; bound the parsed tree as well as the input bytes.
    let doc = roxmltree::Document::parse_with_options(
        &probe.introspection,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 65536,
            entity_resolver: None,
        },
    )
    .map_err(|error| match error {
        roxmltree::Error::NodesLimitReached => Error::ResourceLimit,
        _ => Error::UnsupportedFormat,
    })?;
    let root = doc.root_element();
    if root.tag_name().name() != "node" {
        return Err(Error::UnsupportedFormat);
    }
    let mut interfaces = root.children().filter(|n| {
        n.has_tag_name("interface") && n.attribute("name") == Some("org.freedesktop.login1.Manager")
    });
    let interface = interfaces.next().ok_or(Error::UnsupportedFormat)?;
    if interfaces.next().is_some() {
        return Err(Error::UnsupportedFormat);
    }
    let mut methods = interface
        .children()
        .filter(|n| n.has_tag_name("method") && n.attribute("name") == Some("RebootWithFlags"));
    let method = methods.next().ok_or(Error::UnsupportedFormat)?;
    if methods.next().is_some() {
        return Err(Error::UnsupportedFormat);
    }
    let mut args = method.children().filter(|n| n.has_tag_name("arg"));
    let arg = args.next().ok_or(Error::UnsupportedFormat)?;
    if args.next().is_some()
        || arg.attribute("type") != Some("t")
        || !matches!(arg.attribute("direction"), None | Some("in"))
    {
        return Err(Error::UnsupportedFormat);
    }
    Ok(())
}
fn reboot_via(
    call: impl FnOnce(&str, &str, &str, &str, u64) -> zbus::Result<zbus::Message>,
) -> Reply {
    match call(
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "RebootWithFlags",
        1,
    ) {
        Ok(message)
            if message.message_type() == zbus::message::Type::MethodReturn
                && message.body().deserialize::<()>().is_ok() =>
        {
            Reply::Success
        }
        Err(zbus::Error::MethodError(name, _, _)) => match name.as_str() {
            "org.freedesktop.DBus.Error.NoReply"
            | "org.freedesktop.DBus.Error.Timeout"
            | "org.freedesktop.DBus.Error.TimedOut" => Reply::TimedOutAfterSend,
            "org.freedesktop.DBus.Error.Disconnected" => Reply::DisconnectedAfterSend,
            _ => Reply::ExplicitDenial,
        },
        Err(zbus::Error::InputOutput(error)) if error.kind() == std::io::ErrorKind::TimedOut => {
            Reply::TimedOutAfterSend
        }
        _ => Reply::DisconnectedAfterSend,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Query {
    destination: &'static str,
    path: &'static str,
    interface: &'static str,
    property: Option<&'static str>,
}
fn probe_via(
    effective_uid: u32,
    mut query: impl FnMut(Query) -> Result<String, Error>,
) -> Result<Probe, Error> {
    Ok(Probe {
        effective_uid,
        systemd_version: query(Query {
            destination: "org.freedesktop.systemd1",
            path: "/org/freedesktop/systemd1",
            interface: "org.freedesktop.systemd1.Manager",
            property: Some("Version"),
        })?,
        polkit_version: query(Query {
            destination: "org.freedesktop.PolicyKit1",
            path: "/org/freedesktop/PolicyKit1/Authority",
            interface: "org.freedesktop.PolicyKit1.Authority",
            property: Some("BackendVersion"),
        })?,
        introspection: query(Query {
            destination: "org.freedesktop.login1",
            path: "/org/freedesktop/login1",
            interface: "org.freedesktop.DBus.Introspectable",
            property: None,
        })?,
    })
}

pub(crate) fn native_probe(
    connection: &mut Option<zbus::blocking::Connection>,
) -> Result<Probe, Error> {
    let uid = rustix::process::geteuid().as_raw();
    if uid != 0 {
        return Err(super::firmware::io(PlatformOperation::Reboot, 1));
    }
    // Fixed system bus socket; ignore environment-selected bus addresses.
    let conn =
        zbus::blocking::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
            .map_err(bus_error)?
            .method_timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(bus_error)?;
    let probe = probe_via(uid, |query| {
        let proxy =
            zbus::blocking::Proxy::new(&conn, query.destination, query.path, query.interface)
                .map_err(bus_error)?;
        match query.property {
            Some(property) => proxy.get_property(property).map_err(bus_error),
            None => proxy.call("Introspect", &()).map_err(bus_error),
        }
    })?;
    validate_probe(&probe)?;
    *connection = Some(conn);
    Ok(probe)
}
pub(crate) fn native_reboot(connection: &Option<zbus::blocking::Connection>, flags: u64) -> Reply {
    let Some(conn) = connection else {
        return Reply::NotSent;
    };
    if flags != 1 {
        return Reply::NotSent;
    }
    reboot_via(|destination, path, interface, method, flags| {
        conn.call_method(Some(destination), path, Some(interface), method, &flags)
    })
}
fn bus_error(error: zbus::Error) -> Error {
    match error {
        zbus::Error::InputOutput(e) | zbus::Error::Connection(e, _) => super::firmware::io(
            PlatformOperation::Reboot,
            e.raw_os_error()
                .unwrap_or(if e.kind() == std::io::ErrorKind::TimedOut {
                    110
                } else {
                    5
                }),
        ),
        // An unsupported service/signature is a capability failure; do not invent an errno.
        _ => Error::UnsupportedFormat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> zbus::Message {
        zbus::Message::method_call("/synthetic", "Synthetic")
            .unwrap()
            .build(&())
            .unwrap()
    }
    #[test]
    fn native_probe_queries_only_fixed_system_services() {
        let mut queries = Vec::new();
        let result = probe_via(0, |q| {
            let value = match q.property {
                Some("Version") => "255",
                Some("BackendVersion") => "124",
                _ => "<node/>",
            };
            queries.push(q);
            Ok(value.into())
        })
        .unwrap();
        assert_eq!(result.systemd_version, "255");
        assert_eq!(result.polkit_version, "124");
        assert_eq!(result.introspection, "<node/>");
        assert_eq!(
            queries,
            [
                Query {
                    destination: "org.freedesktop.systemd1",
                    path: "/org/freedesktop/systemd1",
                    interface: "org.freedesktop.systemd1.Manager",
                    property: Some("Version")
                },
                Query {
                    destination: "org.freedesktop.PolicyKit1",
                    path: "/org/freedesktop/PolicyKit1/Authority",
                    interface: "org.freedesktop.PolicyKit1.Authority",
                    property: Some("BackendVersion")
                },
                Query {
                    destination: "org.freedesktop.login1",
                    path: "/org/freedesktop/login1",
                    interface: "org.freedesktop.DBus.Introspectable",
                    property: None
                }
            ]
        );
        let mut count = 0;
        assert_eq!(
            probe_via(0, |_| {
                count += 1;
                Err(super::super::firmware::io(PlatformOperation::Reboot, 13))
            })
            .unwrap_err(),
            super::super::firmware::io(PlatformOperation::Reboot, 13)
        );
        assert_eq!(count, 1);
    }
    #[test]
    fn native_reboot_boundary_has_fixed_endpoint_uint64_and_explicit_reply() {
        let mut count = 0;
        let reply = reboot_via(|destination, path, interface, method, flags| {
            count += 1;
            assert_eq!(
                (destination, path, interface, method, flags),
                (
                    "org.freedesktop.login1",
                    "/org/freedesktop/login1",
                    "org.freedesktop.login1.Manager",
                    "RebootWithFlags",
                    1
                )
            );
            let message = zbus::Message::method_call(path, method)
                .unwrap()
                .destination(destination)
                .unwrap()
                .interface(interface)
                .unwrap()
                .build(&flags)
                .unwrap();
            assert_eq!(message.body().signature().to_string(), "t");
            assert_eq!(message.body().deserialize::<u64>().unwrap(), 1);
            zbus::Message::method_return(&message.header())
                .unwrap()
                .build(&())
        });
        assert_eq!(reply, Reply::Success);
        assert_eq!(count, 1);
    }
    #[test]
    fn native_method_errors_timeouts_disconnects_and_signals_have_distinct_evidence() {
        let req = request();
        for name in [
            "org.freedesktop.DBus.Error.AccessDenied",
            "org.freedesktop.login1.OperationInProgress",
            "org.freedesktop.DBus.Error.UnknownMethod",
            "org.freedesktop.DBus.Error.InvalidArgs",
        ] {
            let error = zbus::Message::error(&req.header(), name)
                .unwrap()
                .build(&"denied")
                .unwrap();
            let reply = reboot_via(|_, _, _, _, _| {
                Err(zbus::Error::MethodError(
                    name.try_into().unwrap(),
                    None,
                    error,
                ))
            });
            assert_eq!(reply, Reply::ExplicitDenial);
        }
        for (kind, want) in [
            (std::io::ErrorKind::TimedOut, Reply::TimedOutAfterSend),
            (std::io::ErrorKind::BrokenPipe, Reply::DisconnectedAfterSend),
        ] {
            assert_eq!(
                reboot_via(|_, _, _, _, _| Err(zbus::Error::InputOutput(
                    std::io::Error::from(kind).into()
                ))),
                want
            );
        }
        for (name, want) in [
            (
                "org.freedesktop.DBus.Error.NoReply",
                Reply::TimedOutAfterSend,
            ),
            (
                "org.freedesktop.DBus.Error.Timeout",
                Reply::TimedOutAfterSend,
            ),
            (
                "org.freedesktop.DBus.Error.Disconnected",
                Reply::DisconnectedAfterSend,
            ),
        ] {
            let error = zbus::Message::error(&req.header(), name)
                .unwrap()
                .build(&"reply unavailable")
                .unwrap();
            assert_eq!(
                reboot_via(|_, _, _, _, _| Err(zbus::Error::MethodError(
                    name.try_into().unwrap(),
                    None,
                    error
                ))),
                want
            );
        }
        let signal = zbus::Message::signal(
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "PrepareForShutdown",
        )
        .unwrap()
        .build(&true)
        .unwrap();
        assert_eq!(
            reboot_via(|_, _, _, _, _| Ok(signal)),
            Reply::DisconnectedAfterSend
        );
        let malformed = zbus::Message::method_return(&req.header())
            .unwrap()
            .build(&true)
            .unwrap();
        assert_eq!(
            reboot_via(|_, _, _, _, _| Ok(malformed)),
            Reply::DisconnectedAfterSend
        );
    }
}
