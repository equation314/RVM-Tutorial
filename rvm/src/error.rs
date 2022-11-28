/// The error type for RVM operations.
#[derive(Debug)]
pub enum RvmError {
    AlreadyExists,
    BadState,
    InvalidParam,
    OutOfMemory,
    ResourceBusy,
    Unsupported,
}

/// A [`Result`] type with [`RvmError`] as the error type.
pub type RvmResult<T = ()> = Result<T, RvmError>;

macro_rules! rvm_err_type {
    ($err: ident) => {{
        use $crate::error::RvmError::*;
        warn!("[RvmError::{:?}]", $err);
        $err
    }};
    ($err: ident, $msg: expr) => {{
        use $crate::error::RvmError::*;
        warn!("[RvmError::{:?}] {}", $err, $msg);
        $err
    }};
}

macro_rules! rvm_err {
    ($err: ident) => {
        Err(rvm_err_type!($err))
    };
    ($err: ident, $msg: expr) => {
        Err(rvm_err_type!($err, $msg))
    };
}
