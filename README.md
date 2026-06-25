# Aya+Rust uprobe tools
## postsniff_demo
Keeps count of the current number of inserts/selects/other query types by hooking into
postgres' `pg_parse_query` function.

## postdrop_demo
Very rudimentarily prevents drops by replacing anything starting with `DROP TABLE`
with `SELECT NULL;` (also by hooking into postgres' `pg_parse_query` function).

## Generate Project
`cargo generate https://github.com/aya-rs/aya-template`

## Build
`cargo build` (needs rust-src installed) (follow aya tutorial)

## Run
Either `cargo run` or using a sudo alternative of your preference (e.g. `doas ./target/debug/postsniff_demo`)

