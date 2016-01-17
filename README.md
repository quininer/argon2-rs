argon2-rs
=========

Rust bindings for [Argon2](https://github.com/P-H-C/phc-winner-argon2).

Requirements
------------

+ Argon2
	* Arch user can install from [AUR](https://aur.archlinux.org/packages/argon2-git/).
+ Clang
	* Generate `ffi.rs`.

Build
-----

You can use environment variables to specify include path.

fish:

	set -x INCLUDE_PATH /usr/local/include/
	set -x CLANG_INCLUDE_PATH /usr/lib/clang/3.4.0/include/

bash:

	export INCLUDE_PATH=/usr/local/include/
	export CLANG_INCLUDE_PATH=/usr/lib/clang/3.4.0/include/
