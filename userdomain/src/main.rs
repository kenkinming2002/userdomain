use std::{net::Ipv4Addr, str::FromStr, time::Duration};

use anyhow::Result;
use argh::{FromArgValue, FromArgs};
use dbus::{Signature, arg::{Append, Arg, ArgType}, blocking::Connection};

/// Frontend to userdomain daemon.
///
/// Communicate with running userdomain daemon via dbus.
#[derive(FromArgs, PartialEq, Debug)]
struct Args {
    #[argh(subcommand)]
    subcommand: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Create(SubCommandCreate),
    Remove(SubCommandRemove),
    Resolve(SubCommandResolve),
    ReverseResolve(SubCommandReverseResolve),
}

/// Create user domain of the form "<name>.<username>.local".
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "create")]
struct SubCommandCreate {
    /// name of the created user domain
    #[argh(positional)]
    name: String,

    /// list of port redirections (e.g. 80:8080)
    #[argh(positional)]
    redirs: Vec<RedirArg>,
}

/// Remove user domain.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "remove")]
struct SubCommandRemove {
    /// address of created user domain
    #[argh(positional)]
    address: AddressArg,
}

/// Resolve a domain.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "resolve")]
struct SubCommandResolve {
    /// domain to resolve
    #[argh(positional)]
    domain: String,
}

/// ReverseResolve a domain.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "reverse-resolve")]
struct SubCommandReverseResolve {
    /// address to reverse resolve
    #[argh(positional)]
    address: AddressArg,
}

#[derive(PartialEq, Debug)]
struct RedirArg {
    port_from: u16,
    port_to: u16,
}

impl FromArgValue for RedirArg {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let mut components = value.split(':');

        let port_from = components.next().ok_or_else(|| format!("missing source port"))?;
        let port_from = port_from.parse().map_err(|e| format!("failed to parse '{port_from}' as port number: {e}"))?;

        let port_to = components.next().ok_or_else(|| format!("missing destination port"))?;
        let port_to = port_to.parse().map_err(|e| format!("failed to parse '{port_to}' as port number: {e}"))?;

        if components.next().is_some() {
            Err(format!("too many components"))?
        }

        Ok(Self { port_from, port_to })
    }
}

impl Arg for RedirArg {
    const ARG_TYPE: ArgType = <(u16, u16) as Arg>::ARG_TYPE;
    fn signature() -> Signature<'static> {
        <(u16, u16) as Arg>::signature()
    }
}

impl Append for RedirArg {
    fn append_by_ref(&self, iter: &mut dbus::arg::IterAppend) {
        (self.port_from, self.port_to).append_by_ref(iter);
    }
}

#[derive(PartialEq, Debug)]
struct AddressArg(u32);

impl FromArgValue for AddressArg {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let addr = Ipv4Addr::from_str(value).map_err(|e| e.to_string())?;
        let addr = addr.to_bits();
        Ok(Self(addr))
    }
}

impl Arg for AddressArg {
    const ARG_TYPE: ArgType = <u32 as Arg>::ARG_TYPE;
    fn signature() -> Signature<'static> {
        <u32 as Arg>::signature()
    }
}

impl Append for AddressArg {
    fn append_by_ref(&self, iter: &mut dbus::arg::IterAppend) {
        self.0.append_by_ref(iter);
    }
}

fn main() -> Result<()> {
    let args = argh::from_env::<Args>();

    let conn = Connection::new_system()?;
    let proxy = conn.with_proxy("org.UserDomain", "/", Duration::from_millis(5000));

    match args.subcommand {
        SubCommand::Create(SubCommandCreate { name, redirs }) => {
            let (address,): (u32,) = proxy.method_call("org.UserDomain", "Create", (name, redirs))?;
            let address = Ipv4Addr::from_bits(address);
            println!("{address}");
        },
        SubCommand::Remove(SubCommandRemove { address }) => {
            let () = proxy.method_call("org.UserDomain", "Remove", (address,))?;
        },
        SubCommand::Resolve(SubCommandResolve { domain }) => {
            let (addresses,): (Vec<u32>,) = proxy.method_call("org.UserDomain", "Resolve", (domain,))?;
            for address in addresses {
                let address = Ipv4Addr::from_bits(address);
                println!("{address}");
            }
        },
        SubCommand::ReverseResolve(SubCommandReverseResolve { address }) => {
            let (domain,): (String,) = proxy.method_call("org.UserDomain", "ReverseRemove", (address,))?;
            println!("{domain}");
        },
    }

    Ok(())
}
