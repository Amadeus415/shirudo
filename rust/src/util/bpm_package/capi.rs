// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls.

use core::ffi::{CStr, c_char, c_int};

use super::archive::{self, Found};
use super::{PackageInfo, info, semver};
use crate::ffi;

/// A C string the caller may pass as NULL.
///
/// # Safety
///
/// `s` is NULL or a C string valid for `'a`.
unsafe fn opt_bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller passes NULL or a C string.
    (!s.is_null()).then(|| unsafe { ffi::c_str(s) })
}

/// # Safety
///
/// `s` is NULL or a C string.
pub unsafe extern "C" fn bpm_semver_valid(s: *const c_char) -> bool {
    // SAFETY: the caller passes NULL or a C string.
    unsafe { opt_bytes(s) }.is_some_and(semver::valid)
}

/// # Safety
///
/// `archive` and `member` are NULL or C strings, and `out` and `out_len`
/// take the member.
pub unsafe extern "C" fn bpm_pkg_read_member(
    archive: *const c_char,
    member: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
    max: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or C strings and the two outputs.
    unsafe {
        let mut found = Found {
            out: &mut *out,
            out_len: &mut *out_len,
            dir: None,
        };

        if archive.is_null() {
            return -crate::errno::EINVAL;
        }
        archive::read_member_in(
            CStr::from_ptr(archive),
            opt_bytes(member),
            None,
            &mut found,
            max,
        )
    }
}

/// # Safety
///
/// `archive` is NULL or a C string and `info` a package info, its cert
/// NULL or one `xfree()` may release.
pub unsafe extern "C" fn bpm_pkg_load_info(
    archive: *const c_char,
    info: *mut PackageInfo,
) -> c_int {
    if archive.is_null() {
        return -crate::errno::EINVAL;
    }
    // SAFETY: the caller passes a C string and its info.
    unsafe { info::load_info(CStr::from_ptr(archive), &mut *info) }
}
