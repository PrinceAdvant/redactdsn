# redactdsn

Mask passwords and tokens in database connection strings before they reach logs, error trackers or support tickets. A small Rust library and CLI with no dependencies.

```
$ redactdsn 'postgres://app:s3cret@db:5432/app?sslmode=require'
postgres://app:***@db:5432/app?sslmode=require

$ docker compose logs app | redactdsn
```

## What it masks

- The password part of the userinfo in any `scheme://user:password@host` URL: Postgres, MySQL, Redis, MongoDB, AMQP and so on.
- Query parameters that usually carry secrets: `password`, `pass`, `pwd`, `token`, `secret`, `key`, `sslpassword`, `apikey`, `api_key`, `access_token`.

Usernames, hosts, ports, database names and other parameters are kept, because those are exactly what you need when debugging which database an app is trying to reach.

## Library

```rust
let safe = redactdsn::redact(&std::env::var("DATABASE_URL").unwrap_or_default());
eprintln!("connecting to {safe}");

let line = redactdsn::redact_text("error: could not connect to redis://:pw@cache:6379");
```

## Install

```
cargo install redactdsn
```

## Why

`DATABASE_URL` is convenient, and it means the password travels with the hostname everywhere the URL is printed: startup banners, connection errors, panic messages and CI output. Redacting at the point of logging is cheaper than rotating credentials after a leak. See how Peon runs [self-hosted databases](https://peon.sh/solutions/databases) with credentials injected at runtime rather than stored in code. Built by a contributor to [Peon](https://peon.sh/), an open-source self-hosted deployment platform.

MIT licensed.
