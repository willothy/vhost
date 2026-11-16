// SPDX-License-Identifier: Apache-2.0

//! The postcopy userfaultfd, through the kernel's ioctl interface directly:
//! the `userfaultfd` crate generates its bindings with bindgen at build
//! time, which puts libclang and kernel headers in the build of every
//! backend that enables postcopy.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `_IOWR(0xAA, 0x3F, struct uffdio_api)`.
const UFFDIO_API: libc::c_ulong = 0xc018_aa3f;
/// `_IOWR(0xAA, 0x00, struct uffdio_register)`.
const UFFDIO_REGISTER: libc::c_ulong = 0xc020_aa00;
/// `_IO(0xAA, 0x00)` on `/dev/userfaultfd`: create a userfaultfd.
const USERFAULTFD_IOC_NEW: libc::c_ulong = 0x0000_aa00;
/// `UFFD_API`.
const UFFD_API: u64 = 0xaa;
/// `UFFD_FEATURE_EVENT_UNMAP`.
const UFFD_FEATURE_EVENT_UNMAP: u64 = 1 << 6;
/// `UFFDIO_REGISTER_MODE_MISSING`.
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioRegister {
    start: u64,
    len: u64,
    mode: u64,
    ioctls: u64,
}

/// A userfaultfd that reports missing faults on the ranges registered with
/// it, and the unmapping of those ranges.
pub(crate) struct Uffd {
    fd: OwnedFd,
}

impl Uffd {
    /// Create a nonblocking, close-on-exec userfaultfd with
    /// `UFFD_FEATURE_EVENT_UNMAP`, handling kernel-mode faults too. Opens
    /// `/dev/userfaultfd`, whose file permissions govern access, and when
    /// that fails falls back to the `userfaultfd(2)` syscall, which needs
    /// privilege unless `vm.unprivileged_userfaultfd` is set.
    pub(crate) fn create() -> io::Result<Self> {
        let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = match File::options()
            .read(true)
            .write(true)
            .open("/dev/userfaultfd")
        {
            Ok(device) => {
                // SAFETY: USERFAULTFD_IOC_NEW on the open device takes the
                // new descriptor's flags by value and returns it.
                let raw =
                    unsafe { libc::ioctl(device.as_raw_fd(), USERFAULTFD_IOC_NEW as _, flags) };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: the ioctl returned a fresh descriptor we now own.
                unsafe { OwnedFd::from_raw_fd(raw) }
            }
            Err(_) => {
                // SAFETY: the userfaultfd syscall takes its flags by value
                // and returns a fresh descriptor or -1.
                let raw = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: the syscall returned a fresh descriptor we now own.
                unsafe { OwnedFd::from_raw_fd(raw as i32) }
            }
        };

        let mut api = UffdioApi {
            api: UFFD_API,
            features: UFFD_FEATURE_EVENT_UNMAP,
            ioctls: 0,
        };
        // SAFETY: `api` is a correctly sized uffdio_api for this ioctl.
        if unsafe { libc::ioctl(fd.as_raw_fd(), UFFDIO_API as _, &mut api) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if api.features & UFFD_FEATURE_EVENT_UNMAP == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the kernel's userfaultfd lacks UFFD_FEATURE_EVENT_UNMAP",
            ));
        }
        Ok(Self { fd })
    }

    /// Register `[addr, addr + len)` for missing faults.
    pub(crate) fn register(&self, addr: u64, len: u64) -> io::Result<()> {
        let mut register = UffdioRegister {
            start: addr,
            len,
            mode: UFFDIO_REGISTER_MODE_MISSING,
            ioctls: 0,
        };
        // SAFETY: `register` is a correctly sized uffdio_register for this
        // ioctl; the kernel validates the range against this process's
        // mappings.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), UFFDIO_REGISTER as _, &mut register) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A second descriptor for this userfaultfd, to hand to the front-end.
    pub(crate) fn try_clone_file(&self) -> io::Result<File> {
        Ok(File::from(self.fd.try_clone()?))
    }
}
