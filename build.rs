#![feature(rustc_private)]

extern crate syntax;
extern crate crustacean;

use std::fs::File;
use std::io::Write;
use syntax::print::pprust;
use crustacean::Generator;


fn main() {
    let mut buff = Vec::new();
    let mut fs = File::create("src/ffi.rs").unwrap();

    for item in Generator::new()
        .header("/usr/include/argon2.h", &["-I/usr/lib/clang/3.7.1/include/"])
        .generate()
        .unwrap()
        .items
    {
        write!(buff, "{}\n", pprust::item_to_string(&item)).unwrap();
    }

    fs.write(
        String::from_utf8_lossy(&buff)
            .replace("\n    ARGON2_VERSION_NUMBER = 19,", "")
            .replace("\
extern \"C\" {\n", "\
#[link(name = \"argon2\")]
extern \"C\" {\n"
            )
            .as_bytes()
    ).unwrap();
}
