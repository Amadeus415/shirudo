// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C interface of `util/eventlog.h`.

use core::ffi::{CStr, c_char, c_int, c_void};

use super::records::{self, EventlogInit, LineFn, UpatchFn};
use crate::ffi;
use crate::util::json::JsonEmit;

#[unsafe(no_mangle)]
pub extern "C" fn eventlog_path() -> *const c_char {
    super::path().as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn eventlog_pending_path() -> *const c_char {
    super::pending_path().as_ptr()
}

/// # Safety
///
/// `json_line` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_append(json_line: *const c_char) -> c_int {
    // SAFETY: the caller passes a C string.
    super::append(unsafe { CStr::from_ptr(json_line) })
}

/// # Safety
///
/// `path` and `json_line` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_append_to(
    path: *const c_char,
    json_line: *const c_char,
) -> c_int {
    // SAFETY: the caller passes two C strings.
    unsafe { super::append_to(CStr::from_ptr(path), CStr::from_ptr(json_line)) }
}

#[unsafe(no_mangle)]
pub extern "C" fn eventlog_adopt_pending() -> c_int {
    super::adopt_pending_locked()
}

#[unsafe(no_mangle)]
pub extern "C" fn eventlog_lock() -> c_int {
    super::lock()
}

#[unsafe(no_mangle)]
pub extern "C" fn eventlog_unlock(fd: c_int) {
    super::unlock(fd)
}

/// # Safety
///
/// `out` has room for a digest.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_replay(out: *mut u8) -> c_int {
    // SAFETY: the caller passes room for 32 bytes.
    records::replay(unsafe { &mut *out.cast::<[u8; 32]>() })
}

/// # Safety
///
/// `out` is an init record to fill.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_boot_init(out: *mut EventlogInit) -> c_int {
    // SAFETY: the caller passes the structure, all of whose bits zeroed
    // are a valid one.
    unsafe {
        out.write_bytes(0, 1);
        records::boot_init(&mut *out)
    }
}

/// # Safety
///
/// `cb` takes `ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_boot_lines(cb: Option<LineFn>, ctx: *mut c_void) -> c_int {
    records::boot_lines(cb, ctx)
}

/// # Safety
///
/// `operation_digest` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_tree_op_measured(
    seq: i64,
    operation_digest: *const c_char,
) -> c_int {
    // SAFETY: the caller passes a C string.
    records::tree_op_measured(seq, unsafe { ffi::c_str(operation_digest) })
}

/// # Safety
///
/// `cb` takes `ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_boot_upatches(cb: Option<UpatchFn>, ctx: *mut c_void) -> c_int {
    records::upatches(false, cb, ctx)
}

/// # Safety
///
/// `cb` takes `ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_upatches(cb: Option<UpatchFn>, ctx: *mut c_void) -> c_int {
    records::upatches(true, cb, ctx)
}

#[unsafe(no_mangle)]
pub extern "C" fn eventlog_would_exceed(max_bytes: u64) -> c_int {
    super::would_exceed(max_bytes)
}

/// # Safety
///
/// `out` has room for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_timestamp(out: *mut c_char, cap: usize) {
    // SAFETY: the caller passes the room.
    super::timestamp(unsafe { ffi::bytes_mut(out.cast(), cap) })
}

/// # Safety
///
/// `out` has room for `cap` bytes, at least one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_boot_id(out: *mut c_char, cap: usize) {
    // SAFETY: the caller passes the room.
    super::read_boot_id(unsafe { ffi::bytes_mut(out.cast(), cap) })
}

/// # Safety
///
/// `e` is an emitter, `ty` a C string and `digest` holds 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventlog_record_open(
    e: *mut JsonEmit,
    ty: *const c_char,
    digest: *const u8,
) {
    // SAFETY: the caller passes its emitter, a C string and a digest.
    unsafe { super::record_open(&mut *e, ffi::c_str(ty), &*digest.cast::<[u8; 32]>()) }
}
