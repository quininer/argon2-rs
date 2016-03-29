extern crate libc;

mod ffi;

use std::fmt;
use std::ffi::{ CString, CStr };
use std::mem::{ transmute, transmute_copy };

pub use ffi::argon2_type as Type;
pub use ffi::argon2_error_codes as ErrorCode;
pub use ffi::argon2_version as Version;
pub use ffi::argon2_version_number as VersionNumber;

const OUT_LEN: usize = 32;
const SALT_LEN: usize = 16;
const ENCODE_LEN: usize = 108;


#[derive(Clone, Debug)]
pub struct Argon2 {
    t_const: usize,
    m_const: usize,
    parallelism: usize,
    salt: Vec<u8>,
    ty: Type,
    out_len: usize,
    salt_len: usize,
    encoded_len: usize
}

impl Argon2 {
    pub fn new<S: AsRef<[u8]>>(salt: S, t_const: usize, m_const: usize) -> Argon2 {
        Argon2 {
            t_const: t_const,
            m_const: m_const,
            parallelism: 1,
            salt: salt.as_ref().into(),
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
    pub fn set_len(mut self, len: usize) -> Argon2 {
        self.out_len = len;
        self
    }

    /// # Example
    ///
    /// ```
    /// use argon2::Argon2;
    ///
    /// let a2 = Argon2::new("somesalt", 2, 65536).set_threads(4);
    /// let (_, hash) = a2.hash("password").unwrap();
    ///
    /// assert_eq!(
    ///     hash,
    ///     "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$K6Lm0QepnXT7WT6YsAcR97jqqKSxQp/+/4eFoB41bXw"
    /// );
    /// ```
    pub fn hash<S: AsRef<[u8]>>(&self, pwd: S) -> Result<(Vec<u8>, String), ErrorCode> {
        let pwd = pwd.as_ref();

        unsafe {
            let mut out = Vec::with_capacity(self.out_len);
            out.set_len(self.out_len);
            let mut encoded = Vec::with_capacity(self.encoded_len);
            encoded.set_len(self.encoded_len);

            match transmute(ffi::argon2_hash(
                self.t_const as libc::uint32_t,
                self.m_const as libc::uint32_t,
                self.parallelism as libc::uint32_t,
                transmute_copy(&pwd),
                pwd.len(),
                transmute_copy(&CString::from_vec_unchecked(self.clone().salt)),
                self.salt_len,
                transmute(out.as_mut_ptr()),
                out.len(),
                encoded.as_mut_ptr(),
                encoded.len(),
                self.ty,
                VersionNumber as u32
            )) {
                ErrorCode::OK => Ok((
                    out,
                    CStr::from_ptr(encoded.as_ptr())
                        .to_str().map(|r| r.into()).unwrap()
                )),
                err => Err(err)
            }
        }
    }
}

/// # Example
///
/// ```
/// use argon2::{ Argon2, verify };
///
/// let a2 = Argon2::new("somesalt", 2, 65536);
/// let (_, hash) = a2.hash("password").unwrap();
///
/// assert!(verify(&hash, "password").is_ok());
/// ```
pub fn verify<E: AsRef<str>, S: AsRef<[u8]>>(encoded: E, pwd: S) -> Result<bool, ErrorCode> {
    let encoded = encoded.as_ref();
    let pwd = pwd.as_ref();

    unsafe {
        match transmute(ffi::argon2_verify(
            CString::from_vec_unchecked(encoded.bytes().collect()).as_ptr(),
            transmute_copy(&pwd),
            pwd.len(),
            if encoded.starts_with("$argon2i$") { Type::i } else { Type::d }
        )) {
            ErrorCode::OK => Ok(true),
            err => Err(err)
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
        write!(f, "{}", error_message(*self).unwrap_or(String::from("Unknown")))
    }
}
