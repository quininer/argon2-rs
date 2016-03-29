#[macro_use] extern crate ffigen;

use std::fs::File;
use std::io::Write;

fn main() {
    // FIXME HACK
    let out = gen!("argon2", [ "argon2.h" ]);
    let out = String::from_utf8_lossy(&out);
    let out = out.replace("
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum argon2_version {
    _10 = 16,
    _13 = 19,
    NUMBER = 19,
}
",
    "
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum argon2_version {
    _10 = 16,
    _13 = 19,
}
pub const argon2_version_number: argon2_version = argon2_version::_13;
");
    File::create("src/ffi.rs").unwrap()
        .write(out.as_bytes()).unwrap();
}
