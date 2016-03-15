extern crate ffigen;

use std::env::var;
use std::fs::File;
use std::io::Write;
use ffigen::GenOptions;

const CLANG_INCLUDE_PATH: &'static str = "/usr/lib/clang/3.7.1/include/";
const INCLUDE_PATH: &'static str = "/usr/include/";


fn main() {
    let data = GenOptions::default()
        .arg(&format!("-I{}", var("CLANG_INCLUDE_PATH").unwrap_or(CLANG_INCLUDE_PATH.into())))
        .header(&format!("{}{}", var("INCLUDE_PATH").unwrap_or(INCLUDE_PATH.into()), "argon2.h"))
        .link("argon2")
        .gen();

    File::create("src/ffi.rs").unwrap()
        .write(&data).unwrap();
}
