use std::ffi::CStr;
use std::io;

use libc::{c_int, c_long, syscall, SYS_openat2};

/// Arguments the behavior of the `openat2` syscall.  
///
/// This is not marked as `non_exhaustive` to promote developers
/// handling new fields when they get added; use [`zeroed`] and
/// initialize fields you want to opt-in to a `non_exhaustive`-like
/// experience.
///
/// [`zeroed`]: fn@OpenHow::zeroed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

impl OpenHow {
    /// Returns a fully zeroed `OpenHow` struct, ideal for forward-compatibility.
    pub fn zeroed() -> Self {
        Self {
            flags: 0,
            mode: 0,
            resolve: 0,
        }
    }
}

/// Wrapper around the `openat2` syscall.  
pub fn openat2(dirfd: c_int, pathname: &CStr, open_how: &OpenHow) -> io::Result<c_long> {
    let result = unsafe {
        syscall(
            SYS_openat2,
            dirfd,
            pathname as *const _,
            open_how as *const _,
            size_of::<OpenHow>(),
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

