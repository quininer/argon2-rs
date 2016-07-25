//! ffigen generate.

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_attributes)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use libc::*;

pub type allocate_fptr = extern "C" fn(
    memory: *mut uint8_t,
    bytes_to_allocate: size_t,
) -> ();
pub type deallocate_fptr = extern "C" fn(
    memory: *mut uint8_t,
    bytes_to_allocate: size_t,
) -> ();

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum argon2_error_codes {
    OK = 0,
    OUTPUT_PTR_NULL = -1,
    OUTPUT_TOO_SHORT = -2,
    OUTPUT_TOO_LONG = -3,
    PWD_TOO_SHORT = -4,
    PWD_TOO_LONG = -5,
    SALT_TOO_SHORT = -6,
    SALT_TOO_LONG = -7,
    AD_TOO_SHORT = -8,
    AD_TOO_LONG = -9,
    SECRET_TOO_SHORT = -10,
    SECRET_TOO_LONG = -11,
    TIME_TOO_SMALL = -12,
    TIME_TOO_LARGE = -13,
    MEMORY_TOO_LITTLE = -14,
    MEMORY_TOO_MUCH = -15,
    LANES_TOO_FEW = -16,
    LANES_TOO_MANY = -17,
    PWD_PTR_MISMATCH = -18,
    SALT_PTR_MISMATCH = -19,
    SECRET_PTR_MISMATCH = -20,
    AD_PTR_MISMATCH = -21,
    MEMORY_ALLOCATION_ERROR = -22,
    FREE_MEMORY_CBK_NULL = -23,
    ALLOCATE_MEMORY_CBK_NULL = -24,
    INCORRECT_PARAMETER = -25,
    INCORRECT_TYPE = -26,
    OUT_PTR_MISMATCH = -27,
    THREADS_TOO_FEW = -28,
    THREADS_TOO_MANY = -29,
    MISSING_ARGS = -30,
    ENCODING_FAIL = -31,
    DECODING_FAIL = -32,
    THREAD_FAIL = -33,
    DECODING_LENGTH_FAIL = -34,
    VERIFY_MISMATCH = -35,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct argon2_context {
    pub out: *mut uint8_t,
    pub outlen: uint32_t,
    pub pwd: *mut uint8_t,
    pub pwdlen: uint32_t,
    pub salt: *mut uint8_t,
    pub saltlen: uint32_t,
    pub secret: *mut uint8_t,
    pub secretlen: uint32_t,
    pub ad: *mut uint8_t,
    pub adlen: uint32_t,
    pub t_cost: uint32_t,
    pub m_cost: uint32_t,
    pub lanes: uint32_t,
    pub threads: uint32_t,
    pub version: uint32_t,
    pub allocate_cbk: allocate_fptr,
    pub free_cbk: deallocate_fptr,
    pub flags: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum argon2_type {
    d = 0,
    i = 1,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum argon2_version {
    _10 = 16,
    _13 = 19,
}
pub const argon2_version_number: argon2_version = argon2_version::_13;

#[link(name="argon2")]
extern "C" {
    pub fn argon2_ctx(
        context: *mut argon2_context,
        type_: argon2_type,
    ) -> c_int;
    pub fn argon2i_hash_encoded(
        t_cost: uint32_t,
        m_cost: uint32_t,
        parallelism: uint32_t,
        pwd: *const c_void,
        pwdlen: size_t,
        salt: *const c_void,
        saltlen: size_t,
        hashlen: size_t,
        encoded: *mut c_char,
        encodedlen: size_t,
    ) -> c_int;
    pub fn argon2i_hash_raw(
        t_cost: uint32_t,
        m_cost: uint32_t,
        parallelism: uint32_t,
        pwd: *const c_void,
        pwdlen: size_t,
        salt: *const c_void,
        saltlen: size_t,
        hash: *mut c_void,
        hashlen: size_t,
    ) -> c_int;
    pub fn argon2d_hash_encoded(
        t_cost: uint32_t,
        m_cost: uint32_t,
        parallelism: uint32_t,
        pwd: *const c_void,
        pwdlen: size_t,
        salt: *const c_void,
        saltlen: size_t,
        hashlen: size_t,
        encoded: *mut c_char,
        encodedlen: size_t,
    ) -> c_int;
    pub fn argon2d_hash_raw(
        t_cost: uint32_t,
        m_cost: uint32_t,
        parallelism: uint32_t,
        pwd: *const c_void,
        pwdlen: size_t,
        salt: *const c_void,
        saltlen: size_t,
        hash: *mut c_void,
        hashlen: size_t,
    ) -> c_int;
    pub fn argon2_hash(
        t_cost: uint32_t,
        m_cost: uint32_t,
        parallelism: uint32_t,
        pwd: *const c_void,
        pwdlen: size_t,
        salt: *const c_void,
        saltlen: size_t,
        hash: *mut c_void,
        hashlen: size_t,
        encoded: *mut c_char,
        encodedlen: size_t,
        type_: argon2_type,
        version: uint32_t,
    ) -> c_int;
    pub fn argon2i_verify(
        encoded: *const c_char,
        pwd: *const c_void,
        pwdlen: size_t,
    ) -> c_int;
    pub fn argon2d_verify(
        encoded: *const c_char,
        pwd: *const c_void,
        pwdlen: size_t,
    ) -> c_int;
    pub fn argon2_verify(
        encoded: *const c_char,
        pwd: *const c_void,
        pwdlen: size_t,
        type_: argon2_type,
    ) -> c_int;
    pub fn argon2d_ctx(
        context: *mut argon2_context,
    ) -> c_int;
    pub fn argon2i_ctx(
        context: *mut argon2_context,
    ) -> c_int;
    pub fn argon2d_verify_ctx(
        context: *mut argon2_context,
        hash: *const c_char,
    ) -> c_int;
    pub fn argon2i_verify_ctx(
        context: *mut argon2_context,
        hash: *const c_char,
    ) -> c_int;
    pub fn argon2_verify_ctx(
        context: *mut argon2_context,
        hash: *const c_char,
        type_: argon2_type,
    ) -> c_int;
    pub fn argon2_error_message(
        error_code: c_int,
    ) -> *const c_char;
    pub fn argon2_encodedlen(
        t_cost: uint32_t,
        m_cost: uint32_t,
        parallelism: uint32_t,
        saltlen: uint32_t,
        hashlen: uint32_t,
    ) -> size_t;
}