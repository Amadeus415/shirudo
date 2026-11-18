// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C interface of `util/bpm_package.h`.

use core::ffi::{CStr, c_char, c_int};

use super::archive::{self, Found};
use super::{IndexEntry, PackageInfo, index, info, semver};
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
/// `body` holds `len` bytes, `entries` has room for `BPM_MAX_ENTRIES`
/// entries and `n_entries` is an int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_index_parse(
    body: *const u8,
    len: usize,
    entries: *mut IndexEntry,
    n_entries: *mut c_int,
) -> c_int {
    // SAFETY: the caller passes the body, room for the entries and the
    // count.
    unsafe { index::index_parse(ffi::slice(body, len), entries, &mut *n_entries) }
}

/// # Safety
///
/// `a` and `b` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_semver_compare(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: the caller passes two C strings.
    unsafe { semver::compare(ffi::c_str(a), ffi::c_str(b)) }
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
/// `archive`, `member` and `package_dir` are NULL or C strings,
/// `found_dir` is NULL or has room for `found_dir_sz`, and `out` and
/// `out_len` take the member.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_read_member_in(
    archive: *const c_char,
    member: *const c_char,
    package_dir: *const c_char,
    found_dir: *mut c_char,
    found_dir_sz: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    max: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or C strings, NULL or the room at
    // found_dir, and the two outputs.
    unsafe {
        let mut found = Found {
            out: &mut *out,
            out_len: &mut *out_len,
            dir: (!found_dir.is_null()).then(|| ffi::bytes_mut(found_dir.cast(), found_dir_sz)),
        };

        archive::read_member_in(
            archive,
            opt_bytes(member),
            opt_bytes(package_dir),
            &mut found,
            max,
        )
    }
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

        archive::read_member_in(archive, opt_bytes(member), None, &mut found, max)
    }
}

/// # Safety
///
/// `archive` is NULL or a C string and `dest` a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_extract(archive: *const c_char, dest: *const c_char) -> c_int {
    // SAFETY: the caller passes a C string.
    archive::extract(archive, unsafe { CStr::from_ptr(dest) })
}

/// # Safety
///
/// `archive` is NULL or a C string and `info` a package info, its cert
/// NULL or one `xfree()` may release.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_load_info(
    archive: *const c_char,
    info: *mut PackageInfo,
) -> c_int {
    // SAFETY: the caller passes its info.
    info::load_info(archive, unsafe { &mut *info })
}
