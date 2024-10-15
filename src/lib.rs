//! High-level abstractions of *at-and-related *nix syscalls to build race condition-free,
//! thread-safe, symlink traversal attack-safe user APIs.   
//!
//! ### Motivation
//!
//! While building filesystem-abstracting APIs, you can easily run into race conditions: classic
//! system calls, as exposed by Rust's filesystem library, often [do not provide sufficient
//! protections in multi-threaded or multi-process applications](https://tldp.org/HOWTO/Secure-Programs-HOWTO/avoid-race.html).  
//!
//! In more complex applications, especially if they run as root, you risk exposing yourself to
//! time-of-check time-of-use (TOCTOU) race conditions, which can culminate to privilege escalation
//! vulnerabilities. Up until recently, [`std::fs::remove_dir_all`] was [sensitive to this attack
//! vector](https://github.com/rust-lang/rust/security/advisories/GHSA-r9cc-f5pr-p3j2).  
//!
//! Unfortunately, avoiding these race conditions is not an easy task. You need to directly
//! interact with specialized system calls, handle different operating systems and `unsafe` code.
//! This library aims to provide a safe, easy to use yet ultra flexible API which doesn't hide away
//! any implementation details.
//!
//! ### Do I need to use sneak?
//!
//! If your application accesses and modifies a filesystem tree at the same time as another thread
//! or another process, especially if one of these processes runs as root, you should use sneak or
//! any similar library.
//!
//! ### Getting started
//!
//! Add the library to your `Cargo.toml`:
//!
//! ```toml
//! sneak = "0.1.0"
//! ```
//!
//! Use [`Dir`] to open a starting trusted directory.  
//!
//! ```
//! use sneak::Dir;
//!
//! let base_dir = Dir::open(BASE_DIR)?;
//!
//! println!("uid({})", base_dir.fstat()?.uid());
//! ```
//!
//! You can use it within your application to secure your filesystem interactions:
//!
//! ```
//! use sneak::Dir;
//!
//! #[post("/files/upload")]
//! fn upload(request: &Request, data: Vec<u8>) -> anyhow::Result<()> {
//!     let user_dir: PathBuf = directory_of_user(request.user_id);
//!     let user_dir = Dir::open(&user_dir)?;
//!
//!     // if another application has access to these files at the same time
//!     // as our API, we can avoid race conditions with sneak:
//!     let mut data_file = user_dir.open_file(format!("user_data/{}/data.bin", request.user_id))?;
//!
//!     // set correct file permissions
//!     data_file.fchown(request.user_uid, request.user_gid)?;
//!
//!     // write the data
//!     data_file.write_all(&data)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Async support
//!
//! A crate like this cannot support async without being runtime-specific. Though, using it as part
//! of your async codebase should be easy: just wrap the syscall-calling operations in your
//! runtime's `spawn_blocking` function. This includes all methods on [`Dir`], as well as its
//! [`Drop`] implementation.
//!
//! ```
//! use std::path::PathBuf;
//! use std::io;
//!
//! use sneak::Dir;
//! use tokio::task::spawn_blocking;
//! use tokio::fs::File;
//!
//! /// Example with Tokio.
//! async fn open_file_async(base_dir: PathBuf, filepath: PathBuf) -> io::Result<File> {
//!     spawn_blocking(move || {
//!         let file = Dir::open(&base_dir)?.open_file(&filepath)?;
//!         Ok(File::from_std(file))
//!     }).await.expect("I/O task not to panic")
//! }
//! ```
//!
//! ### OS Support
//!
//! Most *nix systems should work, though this is only tested against Linux currently. Some patches
//! are applied for MacOS.
//!
//! ### Prior art
//!
//! The [`openat`](https://docs.rs/openat/latest/openat/) crate is more widely used and exposes a few
//! more methods, but lacks some flexibility I personally needed.  
//!
//! ### License
//!
//! This software is dual-licensed under the MIT license and the Apache-2.0 license.

use std::ffi::{c_int, CStr, CString};
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, mem, ptr, slice};

#[cfg(target_os = "windows")]
compile_error!("crate `sneak` is not supported on Windows.");

#[cfg(not(target_os = "macos"))]
use libc::{
    close, dev_t, fchown, fstat, ino_t, open, openat, stat, time_t, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_PATH, O_RDONLY
};
#[cfg(target_os = "macos")]
use libc::{
    close, dev_t, fchown, fstat, ino_t, open, openat, stat, time_t, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_RDONLY
};
#[cfg(target_os = "macos")]
const O_PATH: c_int = 0;

/// A owned reference to an opened directory. This reference is automatically cleaned up on drop.
pub struct Dir {
    fd: c_int,
    flags: c_int,
}

impl Dir {
    /// Opens the directory using a normal `open(2)` syscall.  
    ///
    /// This does not follow symbolic links.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let fd = unsafe {
            cstr(path.as_ref().as_os_str().as_bytes(), &|s| {
                open(
                    s.as_ptr(),
                    O_DIRECTORY | O_PATH | O_NOFOLLOW | O_CLOEXEC | O_RDONLY,
                )
            })
        };

        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Dir {
                fd,
                flags: default_flags(),
            })
        }
    }

    /// Overrides the open flags used by [`Dir::open_dirs`] or [`Dir::open_file`]. Use flags
    /// prefixed by `O_` in [`libc`].
    ///
    /// When opening directories, the [`O_RDONLY`] flags is always used.  
    ///
    /// # Important flags
    ///
    /// [`O_NOFOLLOW`]: This flag prevents symlinks from being followed. Handling symlinks in a
    /// race-condition free way can be tedious and heavily depends on your use case; it is
    /// therefore recommended to never follow symlinks.  
    ///
    /// [`O_PATH`]: Using this flag means the file or directory won't actually be opened; the
    /// resulting file descriptor can only be used by *at syscalls (like with the [`Dir::open_dirs`] and
    /// [`Dir::open_file`] methods) and other limited scenarios. Files and directories with this
    /// flag will not be able to be **read**, **written to** and other file operations won't be
    /// available, including **changing ownership of the file**. Using this flag can lessen filesystem
    /// load in some cases, by not updating `atime` for example. **Note this flag is not available on
    /// MacOS systems**.
    ///
    /// # Example
    /// ```
    /// use sneak::{default_flags, Dir};
    /// use libc::O_PATH;
    ///
    /// // open ./db/data.bin without modifying their `atime`, free of race conditions and
    /// // traversal attacks.
    /// let data_file = Dir::open(base_path)?
    ///     .with_flags(default_flags() | O_PATH)
    ///     .open_file("./db/data.bin")
    /// ```
    ///
    /// [`O_NOFOLLOW`]: const@::libc::O_NOFOLLOW
    /// [`O_PATH`]: const@::libc::O_PATH
    /// [`O_RDONLY`]: const@::libc::O_RDONLY
    pub fn with_flags(self, flags: i32) -> Self {
        Dir { fd: self.fd, flags }
    }

    /// Recursively opens every directory in the given path, returning the first encountered error
    /// or the leaf directory.  
    ///
    /// Note that:
    /// - Prefix (`..`) components are respected and saturate if they recurse behind the current
    ///   directory (i.e. `./dir/../../../subdir` just resolves to `./subdir`.)
    /// - Current directory (`.`) and root directory prefixes (leading `/`) components are ignored.
    /// - Windows-specific path components raise a [`NotFound`] error.  
    ///
    /// Note the original directory `self` is kept open until it is dropped.   
    ///
    /// Symbolic links are not followed unless you've overridden the flags with [`Dir::with_flags`] to
    /// not contain [`O_NOFOLLOW`].
    ///
    ///
    /// # Example
    /// ```
    /// use sneak::Dir;
    ///
    /// // open directories ./user/store/data in `base_path`, free of race conditions and traversal attacks.
    /// let dir = Dir::open(base_path)?.open_dirs("./user/store/data")?;
    ///
    /// // use dir...
    ///
    /// ```
    ///
    /// [`NotFound`]: type@std::io::ErrorKind::NotFound
    /// [`O_NOFOLLOW`]: const@::libc::O_NOFOLLOW
    pub fn open_dirs<P: AsRef<Path>>(&self, path: P) -> io::Result<Dir> {
        let mut path_buf = PathBuf::new();

        for c in path.as_ref().components() {
            match c {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    let _ = path_buf.pop();
                }
                Component::Normal(s) => path_buf.push(s),
                Component::Prefix(_) => return Err(io::ErrorKind::NotFound.into()),
            }
        }

        let mut prev_fd = self.fd;

        for c in path_buf.components() {
            if let Component::Normal(os_str) = c {
                let new_fd = unsafe {
                    cstr(os_str.as_bytes(), &|cstr| {
                        openat(prev_fd, cstr.as_ptr(), self.flags | O_RDONLY)
                    })
                };

                if new_fd < 0 {
                    return Err(io::Error::last_os_error());
                }

                let result = if prev_fd == self.fd {
                    0
                } else {
                    unsafe { close(prev_fd) }
                };

                prev_fd = new_fd;

                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        if prev_fd == self.fd {
            const CUR_DIR: &CStr = match CStr::from_bytes_with_nul(b".\0") {
                Ok(cstr) => cstr,
                Err(_) => unreachable!(),
            };

            let new_fd = unsafe { openat(self.fd, CUR_DIR.as_ptr(), self.flags | O_RDONLY) };

            if new_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            prev_fd = new_fd;
        }

        Ok(Dir {
            fd: prev_fd,
            flags: self.flags,
        })
    }

    /// Recursively opens every directory in the given path, then opens the last component as a
    /// file, returning the file handle or the first error.  
    ///
    /// The same path component rules as [`Dir::open_dirs`] are applied, with the exception that
    /// the last component of the path must be a normal component (not a prefix `..` or current
    /// directory `.` component) and is treated as a file. The input path must also not be empty.
    /// If one of these conditions is violated, this returns [`IsADirectory`] or [`NotFound`].
    ///
    /// When opening the file, default flags or flags set with [`Dir::with_flags`] are used, except
    /// the [`O_DIRECTORY`] flags which is removed.  
    ///
    /// These flags are bit-ORed with the `extra_flags` argument, which is meant for file
    /// opening-specific flags like [`O_WRONLY`]. You may use flags such as [`O_CREAT`] or [`O_EXCL`],
    /// but you *must* specify at least one of [`O_RDONLY`], [`O_WRONLY`] or [`O_RDWR`].
    ///
    /// # Example
    ///
    /// ```
    /// use sneak::Dir;
    /// use libc::{O_CREAT, O_WRONLY};
    ///
    /// let dir = Dir::open(base_dir)?;
    ///
    /// // open the file for writing, creating it if it doesn't exist
    /// let mut file = dir.open_file("./subfolder/data.txt", O_CREAT | O_WRONLY)?;
    /// file.write_all(my_data)?;
    /// ```
    ///
    /// [`O_DIRECTORY`]: const@::libc::O_DIRECTORY
    /// [`IsADirectory`]: type@std::io::ErrorKind::IsADirectory
    /// [`NotFound`]: type@std::io::ErrorKind::NotFound
    /// [`O_RDONLY`]: const@::libc::O_RDONLY
    /// [`O_WRONLY`]: const@::libc::O_WRONLY
    /// [`O_RDWR`]: const@::libc::O_RDWR
    /// [`O_CREAT`]: const@::libc::O_CREAT
    /// [`O_EXCL`]: const@::libc::O_EXCL
    pub fn open_file<P: AsRef<Path>>(&self, path: P, extra_flags: i32) -> io::Result<File> {
        let mut path_buf = PathBuf::new();
        let mut filename = None;

        let mut components = path.as_ref().components().peekable();

        loop {
            let Some(c) = components.next() else {
                break;
            };

            if components.peek().is_some() {
                match c {
                    Component::RootDir | Component::CurDir => {}
                    Component::ParentDir => {
                        let _ = path_buf.pop();
                    }
                    Component::Normal(s) => path_buf.push(s),
                    Component::Prefix(_) => return Err(io::ErrorKind::NotFound.into()),
                }
            } else if let Component::Normal(s) = c {
                filename = Some(s);
            } else if let Component::Prefix(_) = c {
                return Err(io::ErrorKind::NotFound.into());
            }
        }

        let Some(filename) = filename else {
            // IsADirectory is unstable, but it is errno 21.
            return Err(io::Error::from_raw_os_error(21));
        };

        let mut prev_fd = self.fd;

        for c in path_buf.components() {
            if let Component::Normal(os_str) = c {
                let new_fd = unsafe {
                    cstr(os_str.as_bytes(), &|cstr| {
                        openat(prev_fd, cstr.as_ptr(), self.flags | O_RDONLY)
                    })
                };

                if new_fd < 0 {
                    return Err(io::Error::last_os_error());
                }

                let result = if prev_fd == self.fd {
                    0
                } else {
                    unsafe { close(prev_fd) }
                };

                prev_fd = new_fd;

                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        let fd = unsafe {
            cstr(filename.as_bytes(), &|cstr| {
                openat(
                    prev_fd,
                    cstr.as_ptr(),
                    self.flags & !O_DIRECTORY | extra_flags,
                )
            })
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safety: the file descriptor just got opened; the File can therefore be the sole
        // owner of it.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Changes ownership of the directory.  
    ///
    /// Note that, if you used the [`O_PATH`] flag with [`Dir::with_flags`], this will always
    /// return an error.
    ///
    /// # Example
    /// ```
    /// use sneak::Dir;
    ///
    /// let dir = Dir::open(base_dir)?.open_dirs("./data")?;
    ///
    /// // change `./data` to be owned
    /// dir.fchown(1000, 1000);
    /// ```
    ///
    /// [`O_PATH`]: const@::libc::O_PATH
    pub fn fchown(&self, uid: u32, gid: u32) -> io::Result<()> {
        let result = unsafe { fchown(self.fd, uid, gid) };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Queries information about the directory.  
    ///
    /// Even if you used the [`O_PATH`] flag with [`Dir::with_flags`], this
    /// should not return an error under normal circumstances.  
    ///
    /// # Example
    /// ```
    /// use sneak::Dir;
    ///
    /// let meta = Dir::open(base_dir)?.fstat()?;
    ///
    /// // print the user ID and group ID of the owner of the directory
    /// println!("uid({}) gid({})", meta.uid(), meta.gid())
    /// ```
    ///
    /// [`O_PATH`]: const@::libc::O_PATH
    pub fn fstat(&self) -> io::Result<Metadata> {
        unsafe {
            let mut st: stat = mem::zeroed();
            let result = fstat(self.fd, (&mut st) as *mut _);

            if result < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Metadata {
                st_dev: st.st_dev,
                st_ino: st.st_ino,
                st_mode: st.st_mode,
                st_nlink: st.st_nlink,
                st_uid: st.st_uid,
                st_gid: st.st_gid,
                st_rdev: st.st_rdev,
                st_size: st.st_size,
                st_atime: st.st_atime,
                st_mtime: st.st_mtime,
                st_ctime: st.st_ctime,
            })
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        if self.fd > 0 {
            unsafe {
                close(self.fd);
            }
        }
    }
}

/// File or directory metadata. This is analogous to the standard library's [`Metadata`].  
///
/// Obtained by calling [`fstat`] on a [`Dir`].
///
/// ```
/// use sneak::Dir;
///
/// let meta = Dir::open(base_dir)?.fstat()?;
///
/// println!("uid({}) gid({})", meta.uid(), meta.gid());
/// ```
///
/// [`fstat`]: fn@crate::Dir::fstat
/// [`Metadata`]: struct@std::fs::Metadata
pub struct Metadata {
    st_dev: dev_t,
    st_ino: ino_t,
    st_mode: u32,
    st_nlink: u64,
    st_uid: u32,
    st_gid: u32,
    st_rdev: dev_t,
    st_size: i64,
    st_atime: time_t,
    st_mtime: time_t,
    st_ctime: time_t,
}

impl Metadata {
    pub fn dev(&self) -> dev_t {
        self.st_dev
    }

    pub fn rdev(&self) -> dev_t {
        self.st_rdev
    }

    pub fn inode(&self) -> ino_t {
        self.st_ino
    }

    pub fn nlink(&self) -> u64 {
        self.st_nlink
    }

    /// The size of the filesystem node. Note that this size is
    /// not recursive for directories; it will most likely be equal
    /// to 4096 bytes.
    pub fn size(&self) -> u64 {
        self.st_size as u64
    }

    /// Returns `true` if this references a directory. This should always return `true` if you got
    /// the [`Metadata`] object from [`Dir::fstat`].
    pub fn is_dir(&self) -> bool {
        (self.st_mode & libc::S_IFMT) == libc::S_IFDIR
    }

    /// Returns `true` if this references a directory. This should always return `false` if you got
    /// the [`Metadata`] object from [`Dir::fstat`].
    pub fn is_file(&self) -> bool {
        (self.st_mode & libc::S_IFMT) == libc::S_IFREG
    }

    /// Returns `true` if this references a directory. This should always return `false` if you got
    /// the [`Metadata`] object from [`Dir::fstat`].
    pub fn is_symlink(&self) -> bool {
        (self.st_mode & libc::S_IFMT) == libc::S_IFLNK
    }

    /// Last-accessed time, also named `atime`.
    pub fn accessed(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.st_atime as u64)
    }

    /// Last-modified time, also named `mtime`.
    pub fn modified(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.st_mtime as u64)
    }

    /// Last-changed time, also named `ctime`.
    pub fn created(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.st_ctime as u64)
    }

    /// User ID of the file owner.
    pub fn uid(&self) -> u32 {
        self.st_uid
    }

    /// Group ID of the file owner.
    pub fn gid(&self) -> u32 {
        self.st_gid
    }
}

/// Returns the default flags used by [`Dir`]. In the majority cases, these
/// flags should be used.
///
/// Flags currently include [`O_NOFOLLOW`], [`O_DIRECTORY`] and [`O_CLOEXEC`].
pub fn default_flags() -> c_int {
    O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC
}

/// This uses the same optimization as the standard library's `&[u8]` -> `CStr` convertion.
///
/// Safety: caller must ensure `bytes` has no nul byte.
#[inline]
unsafe fn cstr<T>(bytes: &[u8], f: &dyn Fn(&CStr) -> T) -> T {
    const STACK_MAX: usize = 384;

    if bytes.len() >= STACK_MAX {
        cstr_alloc(bytes, f)
    } else {
        let mut buf = mem::MaybeUninit::<[u8; STACK_MAX]>::uninit();
        let buf_ptr = buf.as_mut_ptr() as *mut u8;

        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, bytes.len());
            buf_ptr.add(bytes.len()).write(0);
        }

        f(CStr::from_bytes_with_nul_unchecked(unsafe {
            slice::from_raw_parts(buf_ptr, bytes.len() + 1)
        }))
    }
}

/// Safety: caller must ensure `bytes` has no nul byte.
#[cold]
unsafe fn cstr_alloc<T>(bytes: &[u8], f: &dyn Fn(&CStr) -> T) -> T {
    f(&CString::from_vec_unchecked(bytes.to_owned()))
}

#[cfg(test)]
mod test {
    use io::Read;

    use super::*;

    #[test]
    fn open_cwd() -> io::Result<()> {
        let _dir = Dir::open(".")?;

        Ok(())
    }

    #[test]
    fn valid_fd_for_close() -> io::Result<()> {
        let dir = Dir::open(".")?;

        let result = unsafe { libc::close(dir.fd) };
        assert_eq!(result, 0);

        // don't double-close the fd
        mem::forget(dir);

        Ok(())
    }

    #[test]
    fn open_self() -> io::Result<()> {
        let dir = Dir::open(".")?;

        let result = dir.open_dirs(".");

        if let Err(e) = result {
            panic!("failed: {e}");
        }

        Ok(())
    }

    #[test]
    fn open_nothing() -> io::Result<()> {
        let dir = Dir::open(".")?;

        let result = dir.open_dirs("");

        if let Err(e) = result {
            panic!("failed: {e}");
        }

        Ok(())
    }

    #[test]
    fn open_should_not_exist() -> io::Result<()> {
        let dir = Dir::open(".")?;

        let result = dir.open_dirs("i-do-not-exist");

        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(_) => panic!("opening not-existant directory succeeded"),
        }

        Ok(())
    }

    #[test]
    fn open_dir_exists() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subdir1/subdir2")?;

        let dir = Dir::open("./playground")?;

        let result = dir.open_dirs("subdir1/subdir2");

        if let Err(e) = result {
            panic!("failed: {e}");
        }

        Ok(())
    }

    #[test]
    fn open_exists_relative() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subdir1")?;
        std::fs::create_dir_all("./playground/subdir1/subdir2")?;

        let dir = Dir::open("./playground")?;

        let result = dir.open_dirs("./subdir1/subdir2");

        if let Err(e) = result {
            panic!("failed: {e}");
        }

        Ok(())
    }

    #[test]
    fn open_skip_symlink() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subdir1/")?;
        std::fs::create_dir_all("./playground/linked/bad")?;
        std::os::unix::fs::symlink("./playground/linked", "./playground/subdir1/link")?;

        let dir = Dir::open("./playground")?;

        let result = dir.open_dirs("./subdir1/link/bad");

        match result {
            Err(e) => assert_eq!(e.raw_os_error(), Some(20)),
            Ok(_) => panic!("opening symlink succeeded"),
        }

        Ok(())
    }

    #[test]
    fn saturate_dirs() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subdir1")?;
        std::fs::create_dir_all("./playground/subdir3/a")?;

        let dir = Dir::open("./playground")?;

        let result = dir.open_dirs("./playground/subdir1/../../../../../../subdir3");

        match result {
            Err(e) => panic!("failure(saturating open): {e}"),
            Ok(saturated) => {
                if let Err(e) = saturated.open_dirs("a") {
                    panic!("failure(second open): {e}");
                }
            }
        }

        Ok(())
    }

    #[test]
    fn open_file() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subfolder9")?;
        std::fs::write("./playground/subfolder9/data.txt", "helloworld1234")?;

        let dir = Dir::open("./playground")?;

        let result = dir.open_file("subfolder9/data.txt", libc::O_RDONLY);

        match result {
            Err(e) => panic!("failure(open_file): {e}"),
            Ok(mut file) => {
                let mut s = String::new();
                match file.read_to_string(&mut s) {
                    Err(e) => panic!("failed(read): {e}"),
                    Ok(_n) => assert_eq!(s, "helloworld1234"),
                }
            }
        }

        Ok(())
    }

    #[test]
    fn file_fchown() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subfolder9")?;

        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        let dir = Dir::open("./playground")?;

        let result = dir.open_dirs("subfolder9");

        match result {
            Err(e) => panic!("failure(open_dirs): {e}"),
            Ok(dir) => {
                if let Err(e) = dir.fchown(uid, gid) {
                    panic!("failed(fchown): {e}");
                }
            }
        }

        Ok(())
    }

    #[test]
    fn file_fstat() -> io::Result<()> {
        std::fs::create_dir_all("./playground/subfolder9")?;

        let dir = Dir::open("./playground")?;

        let result = dir.open_dirs("subfolder9");

        match result {
            Err(e) => panic!("failure(open_dirs): {e}"),
            Ok(dir) => match dir.fstat() {
                Err(e) => panic!("failed(fstat): {e}"),
                Ok(meta) => assert_eq!(meta.size(), 4096),
            },
        }

        Ok(())
    }
}
