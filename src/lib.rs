extern crate libc;

mod ffi;

use std::fmt;
use std::ffi::{ CString, CStr };
use std::mem::{ transmute, transmute_copy };
pub use ffi::{
    argon2_type as Type,
    argon2_error_codes as ErrorCode
};

const OUT_LEN: usize = 32;
const SALT_LEN: usize = 16;
const ENCODE_LEN: usize = 108;


#[derive(Clone, Debug)]
pub struct Argon2 {
    t_const: usize,
    m_const: usize,
    parallelism: usize,
    pwd: Vec<u8>,
    ty: Type,
    out_len: usize,
    salt_len: usize,
    encoded_len: usize
}

impl Argon2 {
    pub fn new(pwd: &[u8], t_const: usize, m_const: usize) -> Argon2 {
        Argon2 {
            t_const: t_const,
            m_const: m_const,
            parallelism: 1,
            pwd: pwd.to_vec(),
            ty: Type::i,
            out_len: OUT_LEN,
            salt_len: SALT_LEN,
            encoded_len: ENCODE_LEN
        }
    }

    pub fn set_threads(mut self, parallelism: usize) -> Argon2 {
        self.parallelism = parallelism;
        self
    }
    pub fn set_type(mut self, ty: Type) -> Argon2 {
        self.ty = ty;
        self
    }

    /// # Example
    ///
    /// ```
    /// use argon2::Argon2;
    ///
    /// let a2 = Argon2::new("password".as_bytes(), 2, 65536);
    /// let (_, hash) = a2.hash("somesalt".as_bytes()).unwrap();
    ///
    /// assert_eq!(
    ///     hash,
    ///     "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$iUr0/y4tJvPOFfd6fhwl20W04gQ56ZYXcroZnK3bAB4"
    /// );
    /// ```
    pub fn hash(&self, salt: &[u8]) -> Result<(Vec<u8>, String), ErrorCode> {
        unsafe {
            let mut out = Vec::with_capacity(self.out_len);
            out.set_len(self.out_len);
            let mut encoded = Vec::with_capacity(self.encoded_len);
            encoded.set_len(self.encoded_len);

            match transmute(ffi::argon2_hash(
                self.t_const as libc::uint32_t,
                self.m_const as libc::uint32_t,
                self.parallelism as libc::uint32_t,
                transmute_copy(&self.pwd),
                self.pwd.len(),
                transmute_copy(&CString::from_vec_unchecked(salt.to_vec())),
                self.salt_len,
                transmute(out.as_mut_ptr()),
                out.len(),
                encoded.as_mut_ptr(),
                encoded.len(),
                self.ty
            )) {
                ErrorCode::OK => Ok((
                    out,
                    CStr::from_ptr(encoded.as_ptr())
                        .to_str().map(|r| r.into()).unwrap()
                )),
                err @ _ => Err(err)
            }
        }
    }

    /// # Example
    ///
    /// ```
    /// use argon2::Argon2;
    ///
    /// let a2 = Argon2::new("password".as_bytes(), 2, 65536);
    /// let (_, hash) = a2.hash("somesalt".as_bytes()).unwrap();
    ///
    /// assert!(a2.verify(&hash).is_ok());
    /// ```
    pub fn verify(&self, encoded: &str) -> Result<bool, ErrorCode> {
        unsafe {
            match transmute(ffi::argon2_verify(
                CString::from_vec_unchecked(encoded.bytes().collect()).as_ptr(),
                transmute_copy(&self.pwd),
                self.pwd.len(),
                self.ty
            )) {
                ErrorCode::OK => Ok(true),
                err @ _ => Err(err)
            }
        }
    }
}

fn error_message(err: ErrorCode) -> Option<String> {
    unsafe {
        CStr::from_ptr(ffi::argon2_error_message(err as libc::c_int))
            .to_str().map(|r| r.into()).ok()
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", error_message(self.clone()).unwrap_or(String::from("Unknown")))
    }
}
