extern crate ffigen;

use std::fs::File;
use std::io::Write;
use ffigen::GenOptions;

const CLANG_INCLUDE_PATH: &'static str = "/usr/lib/clang/3.7.0/include/";
const INCLUDE_PATH: &'static str = "/usr/include/";

fn main() {
    let data = GenOptions::new()
        .arg(&format!("-I{}", CLANG_INCLUDE_PATH))
        .header(&format!("{}{}", INCLUDE_PATH, "argon2.h"))
        .link("argon2")
        .gen();

    File::create("src/ffi.rs").unwrap()
        .write(&data).unwrap();
}
