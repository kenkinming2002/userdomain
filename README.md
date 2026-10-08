# userdomain

Userdomain is a system service that allows each user to registered for local
domain name of the form `<name>.localhost` with port redirections to
priviledged port that is isolated from each other using eBPF technology.

## Aya

This project makes use of [aya]((https://aya-rs.dev/book/)) for building eBPF
program with only rust code. If you encounter any difficulty, you may find
their [documentation]((https://aya-rs.dev/book/)) helpful.

## Building

1. Install required prerequisites by following aya's instructions at
   [Development Environment](https://aya-rs.dev/book/start/development.html).
   There is no need to install `cargo-generate` since you are not generating a
   new project.

2. Compile the project in the usual way using cargo:

```shell
$ cargo build
```

## Example Usage

  - Running the service (This required root permission or relevant capabilities)

     ```shell
     $ ./target/<profile>/userdomain-daemon
     ```

  - Creating a new service with appropriate port redirection:

     ```shell
     $ ./target/<profile>/userdomain create <name> 80:8080
     <address>
     ```

  - **(Optional)** Resolve the created service (TODO: nss module):

     ```shell
     $ ./target/<profile>/userdomain resolve <name>.localhost
     <address>
     ```

  - **(Optional)** Reverse resolve the created service (TODO: nss module):

     ```shell
     $ ./target/<profile>/userdomain reverse-resolve <address>
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
     $ ./target/<profile>/userdomain remove <address>
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
