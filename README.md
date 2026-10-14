# userdomain

Userdomain is a system service that allows each user to registered for local
domain name of the form `<name>.localhost` with port redirections to
priviledged port that is isolated from each other using eBPF technology.

## Aya

This project makes use of [aya]((https://aya-rs.dev/book/)) for building eBPF
program with only rust code. If you encounter any difficulty, you may find
their [documentation]((https://aya-rs.dev/book/)) helpful.

## Prerequisites

Follow aya's instructions at [Development
Environment](https://aya-rs.dev/book/start/development.html). There is no need
to install `cargo-generate` since you are not generating a new project.

## Installation

This project provides a convenient Makefile that bundle together both the
compilation and installation step:

```shell
$ make && sudo make install
```

Alternatively, it is also possible compile the project directly with cargo and
perform the installation on your own:

```shell
$ cargo build --profile release
```

## Command Line Usage

  - Running the service (This required root permission or relevant capabilities)

     ```shell
     $ sudo userdomain-daemon
     ```

  - Creating a new service with appropriate port redirection:

     ```shell
     $ userdomain create <name> 80:8080
     <address>
     ```

  - **(Optional)** Resolve the created service (TODO: nss module):

     ```shell
     $ userdomain resolve <name>.localhost
     <address>
     ```

  - **(Optional)** Reverse resolve the created service (TODO: nss module):

     ```shell
     $ userdomain reverse-resolve <address>
     <name>.localhost
     ```

  - Run netcat server

     ```shell
     $ nc -kl <address> 8080
     ```

  - Run netcat client

     ```shell
     $ nc <address> 80
     ```

  - Remove the service

     ```shell
     $ userdomain remove <address>
     ```

### Name Service Switch (NSS)

This project also provides a nss module that allows you to override domain
lookup globally. If you followed the above installation procedure, a dynamic
library would be installed under /usr/local/lib/libnss_userdomain.so.2.
Depending on your system, it may be necessary update the linker cache by:

```shell
$ sudo ldconfig /usr/local/lib
```

It is also necessary to configure /etc/nsswitch.conf. For example, prepend to
the hosts line such that it changes from:

```
hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
```

to:

```
hosts: userdomain [!UNAVAIL=return] mymachines resolve [!UNAVAIL=return] files myhostname dns
```

such that our installed uss module is used.

## Systemd Service

This project comes with a systemd service. After installation, you could enable
the service with:

```shell
$ systemctl enable userdomain.service
```

## Security

### Priviledged port

Normally, an unprivileged user is prevented from binding to unprivileged port
to prevent it from spoofing as the owner of a system. However, with userdomain,
unprivileged user can essentially 'bind' to priviledged by setting up port
redirection. This is not a concern because:

  1. We uses alternative(excluding 127.0.0.1) loopback addresses which cannot
     be accessed externally(unless sysctl net.ipv4.ip_forward is set).

  2. We setup firewall using eBPF to prevent other non-owning users from
     accessing allocated ip address.

## Licensing

This project is licensed under the MIT license. However, that may not or may
not (I am not a lawyer) include the eBPF code under [userdomain-ebpf/] subject
*only* in addition to the requirement on eBPF code licensing from linux kernel.
