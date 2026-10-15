#![feature(try_blocks)]

use std::{collections::{HashMap, HashSet}, ffi::CStr, mem, net::Ipv4Addr, sync::{Arc, RwLock}, time::Duration};

use anyhow::{Context as _, Result, bail};
use aya::{Ebpf, maps::{HashMap as EbpfHashMap, MapData}, programs::{SchedClassifier, tc::{self, SchedClassifierLinkId, TcAttachType}}};
use aya_log::EbpfLogger;
use dbus::{MethodErr, channel::MatchingReceiver, message::MatchRule, nonblock::{Proxy, SyncConnection, stdintf::org_freedesktop_dbus::RequestNameReply}, strings::BusName};
use dbus_crossroads::Crossroads;
use dbus_tokio::connection;
use tokio::{io::{Interest, unix::AsyncFd}, task};
use userdomain_common::{Addr, REDIR_MAX, Spec};

const MIN_LOOPBACK_ADDRESS: Addr = Addr(Ipv4Addr::new(127, 0, 0, 2));
const MAX_LOOPBACK_ADDRESS: Addr = Addr(Ipv4Addr::new(128, 0, 0, 0));

const BPF_NOEXIST: u64 = 1;

struct UserDomain {
    #[allow(dead_code)] ebpf: Ebpf,
    #[allow(dead_code)] ingress_link: SchedClassifierLinkId,
    #[allow(dead_code)] egress_link: SchedClassifierLinkId,

    spec_map: EbpfHashMap<MapData, Addr, Spec>,

    forward_map: HashMap<(String, String), HashSet<Addr>>,
    backward_map: HashMap<Addr, (String, String)>,

    next_address: Addr,
}

impl UserDomain {
    fn new() -> Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY, };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 { eprintln!("failed to remove limit on locked memory, ret is: {ret}"); }

        // Error adding clsact to the interface if it is already added is harmless The full cleanup
        // can be done with 'sudo tc qdisc del dev eth0 clsact'.
        //
        // TODO: Is it possible to create an additional loopback interface to allocate addresses
        //       from there instead of blindly assuming that the loopback interface have address
        //       127.0.0.1/24 assigned which is unused except for 127.0.0.1.
        //
        let iface = "lo";
        let _ = tc::qdisc_add_clsact("lo");

        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/userdomain")))?;

        let logger = EbpfLogger::init_with_logger(&mut ebpf, env_logger::builder().build()).unwrap();
        let mut logger = AsyncFd::with_interest(logger, Interest::READABLE).unwrap();
        task::spawn(async move {
            loop {
                let mut guard = logger.readable_mut().await.unwrap();
                guard.get_inner_mut().flush();
                guard.clear_ready();
            }
        });

        let program: &mut SchedClassifier = ebpf.program_mut("ingress").unwrap().try_into()?;
        program.load()?;
        let ingress_link = program.attach(&iface, TcAttachType::Ingress)?;

        let program: &mut SchedClassifier = ebpf.program_mut("egress").unwrap().try_into()?;
        program.load()?;
        let egress_link = program.attach(&iface, TcAttachType::Egress)?;

        let spec_map = ebpf.take_map("SPEC_MAP").unwrap().try_into()?;
        let forward_map = Default::default();
        let backward_map = Default::default();
        let next_address = MIN_LOOPBACK_ADDRESS;

        Ok(Self {
            ebpf,
            ingress_link,
            egress_link,
            spec_map,
            forward_map,
            backward_map,
            next_address,
        })
    }

    fn create(&mut self, sender: User, name: String, redirs: Vec<(u16, u16)>) -> Result<(u32,)> {
        if sender.name.contains('.') { bail!("invalid character '.' in sender name {}", sender.name) }
        if name.contains('.') { bail!("invalid character '.' in name {}", name) }

        let address = self.next_address;
        if address == MAX_LOOPBACK_ADDRESS { bail!("loopback addresses exhuasted") }
        self.next_address.0 = Ipv4Addr::from_bits(self.next_address.0.to_bits() + 1);

        let mut spec: Spec = unsafe { mem::zeroed() };
        spec.uid = sender.id;
        spec.redir_count = 0;
        for (port_from, port_to) in redirs {
            if spec.redir_count == REDIR_MAX { bail!("too many port redirections") }
            spec.redirs[spec.redir_count as usize].port_from = port_from.to_be_bytes();
            spec.redirs[spec.redir_count as usize].port_to = port_to.to_be_bytes();
            spec.redir_count += 1;
        }

        self.spec_map.insert(address, spec, BPF_NOEXIST)?; // NOTE: This may fail as BPF map have limited capacity
        let new = self.forward_map.entry((sender.name.clone(), name.clone())).or_default().insert(address); assert!(new);
        let new = self.backward_map.insert(address, (sender.name, name)).is_none();                         assert!(new);

        Ok((address.0.to_bits(),))
    }

    fn remove(&mut self, sender: User, address: u32) -> Result<()> {
        let address = Addr(Ipv4Addr::from_bits(address));

        let (user_name, name) = self.backward_map.get(&address).context("address not registered")?;
        if user_name != &sender.name { bail!("address not registered") /* be opaque about error */ }

        let removed = self.forward_map.get_mut(&(sender.name.clone(), name.clone())).unwrap().remove(&address); assert!(removed);
        let removed = self.backward_map.remove(&address).is_some();                                             assert!(removed);
        self.spec_map.remove(&address).unwrap();

        Ok(())
    }

    fn resolve(&self, sender: User, domain: String) -> Result<(Vec<u32>,)> {
        let mut components = domain.split('.');

        let name = components.next().context("missing name component")?;
        let localhost = components.next().context("missing localhost component")?;
        if components.next().is_some() { bail!("too many components") }
        if localhost != "localhost" { bail!("third component is not localhost") }

        self.forward_map
            .get(&(sender.name.to_owned(), name.to_owned()))
            .map(|addresses| (addresses.into_iter().map(|address| address.0.to_bits()).collect::<Vec<_>>(),))
            .context("domain not registered")
    }

    fn reverse_resolve(&self, sender: User, address: u32) -> Result<(String,)> {
        let address = Addr(Ipv4Addr::from_bits(address));
        let (user_name, name) = self.backward_map.get(&address).context("address not registered")?;
        if user_name != &sender.name { bail!("address not registered") /* be opaque about error */ }
        Ok((format!("{name}.localhost"),))
    }
}

#[derive(Clone, Debug)]
struct User {
    name: String,
    id: u32,
}

/// Get sender user name for a dbus message.
///
/// Implemented following https://qytz-notes.readthedocs.io/tech/dbus/dbus-get-uid.html.
async fn get_connection_user(conn: &SyncConnection, sender: BusName<'_>) -> Result<User> {
    let proxy = Proxy::new("org.freedesktop.DBus", "/", Duration::from_millis(5000), conn);
    let (id,): (u32,) = proxy.method_call("org.freedesktop.DBus", "GetConnectionUnixUser", (&*sender, )).await?;

    let pw = unsafe { libc::getpwuid(id) };
    if pw.is_null() { bail!("failed to lookup passwd entry for uid = {id}") }
    let pw = unsafe { &*pw as &libc::passwd };

    let name = unsafe { CStr::from_ptr(pw.pw_name) };
    let name = name.to_str()?.to_owned();

    Ok(User { name, id })
}

#[tokio::main]
async fn main() -> Result<()> {
    let (res, conn) = connection::new_system_sync()?;

    let mut cr = Crossroads::new();
    cr.set_async_support(Some((conn.clone(), Box::new(|x| { tokio::spawn(x); }))));

    let iface_token = cr.register("org.UserDomain", |b| {
        b.method_with_cr_async("Create", ("name", "redirs"), ("address",), {
            let conn = conn.clone();
            move |mut ctx, cr, (name, redirs)| {
                let conn = conn.clone();
                let object: &mut Arc<RwLock<UserDomain>> = cr.data_mut(ctx.path()).ok_or_else(|| MethodErr::no_path(ctx.path())).unwrap();
                let object = object.clone();
                async move { ctx.reply((try {
                    let sender = ctx.message().sender().context("")?;
                    let sender = get_connection_user(&conn, sender).await?;
                    object.write().unwrap().create(sender, name, redirs)?
                }).map_err(|err| MethodErr::failed(&err))) }
            }
        });

        b.method_with_cr_async("Remove", ("address",), (), {
            let conn = conn.clone();
            move |mut ctx, cr, (address,)| {
                let conn = conn.clone();
                let object: &mut Arc<RwLock<UserDomain>> = cr.data_mut(ctx.path()).ok_or_else(|| MethodErr::no_path(ctx.path())).unwrap();
                let object = object.clone();
                async move { ctx.reply((try {
                    let sender = ctx.message().sender().context("")?;
                    let sender = get_connection_user(&conn, sender).await?;
                    object.write().unwrap().remove(sender, address)?
                }).map_err(|err| MethodErr::failed(&err))) }
            }
        });

        b.method_with_cr_async("Resolve", ("domain",), ("addresses",), {
            let conn = conn.clone();
            move |mut ctx, cr, (domain,)| {
                let conn = conn.clone();
                let object: &mut Arc<RwLock<UserDomain>> = cr.data_mut(ctx.path()).ok_or_else(|| MethodErr::no_path(ctx.path())).unwrap();
                let object = object.clone();
                async move { ctx.reply((try {
                    let sender = ctx.message().sender().context("")?;
                    let sender = get_connection_user(&conn, sender).await?;
                    object.read().unwrap().resolve(sender, domain)?
                }).map_err(|err| MethodErr::failed(&err))) }
            }
        });

        b.method_with_cr_async("ReverseResolve", ("address",), ("domain",), {
            let conn = conn.clone();
            move |mut ctx, cr, (address,)| {
                let conn = conn.clone();
                let object: &mut Arc<RwLock<UserDomain>> = cr.data_mut(ctx.path()).ok_or_else(|| MethodErr::no_path(ctx.path())).unwrap();
                let object = object.clone();
                async move { ctx.reply((try {
                    let sender = ctx.message().sender().context("")?;
                    let sender = get_connection_user(&conn, sender).await?;
                    object.read().unwrap().reverse_resolve(sender, address)?
                }).map_err(|err| MethodErr::failed(&err))) }
            }
        });
    });

    let object = Arc::new(RwLock::new(UserDomain::new()?));
    cr.insert("/", &[iface_token], object);

    conn.start_receive(MatchRule::new_method_call(), Box::new(move |msg, conn| { cr.handle_message(msg, conn).unwrap(); true }));
    let handle = tokio::spawn(res);
    if conn.request_name("org.UserDomain", false /* allow_replacement */, true /* replace_existing */, false /* do_not_queue */).await? != RequestNameReply::PrimaryOwner { bail!("failed to register as primary owner on D-Bus") }
    Err(handle.await?)?
}
