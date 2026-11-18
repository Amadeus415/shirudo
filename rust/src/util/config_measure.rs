// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measurement of a config root: the
//! PCRs a config may be measured into, and the event of a root.

use core::ffi::c_int;

use crate::errno::EINVAL;
use crate::util::crypto_openssl::sha256_buffer;

/// `enum config_event_kind`.
pub(crate) const EVENT_BOOT: c_int = 1;
pub(crate) const EVENT_UPDATE: c_int = 2;

const DOMAIN: &[u8] = b"shirudo-config-root-v1\0";

/// A PCR below 16 other than the register's 9 and 11: 0 or -EINVAL.
pub(crate) fn pcr_valid(pcr: u32) -> c_int {
    if pcr < 16 && pcr != 9 && pcr != 11 {
        0
    } else {
        -EINVAL
    }
}

/// The event that measures a config root: SHA-256 of the domain with its
/// NUL, the kind as a big-endian u32, and the root.
pub(crate) fn event(kind: c_int, root_hash: &[u8; 32], out: *mut u8) -> c_int {
    let mut data = [0u8; DOMAIN.len() + 4 + 32];

    if kind != EVENT_BOOT && kind != EVENT_UPDATE {
        return -EINVAL;
    }
    data[..DOMAIN.len()].copy_from_slice(DOMAIN);
    data[DOMAIN.len() + 3] = kind as u8;
    data[DOMAIN.len() + 4..].copy_from_slice(root_hash);
    // SAFETY: the bytes of data, and the caller's room for a digest.
    unsafe { sha256_buffer(data.as_ptr().cast(), data.len(), out) }
}
