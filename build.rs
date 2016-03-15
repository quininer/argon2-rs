#[macro_use] extern crate ffigen;

fn main() {
    gen!("argon2", [ "argon2.h" ] -> "src/ffi.rs");
}
