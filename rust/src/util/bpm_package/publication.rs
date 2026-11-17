// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Signed payloads: a detached CMS signature checked against a
//! certificate, and the signed tree publication a registry holds.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use crate::errno::{EINVAL, EKEYREJECTED, ENAMETOOLONG, ENOMEM};
use crate::ffi;
use crate::heap::{xcalloc, xfree};
use crate::sys::libc::PATH_MAX;
use crate::text::{contains, cstr, strsprintf};
use crate::util::bpm_oci::{
    BpmBuffer, Descriptor, MANIFEST_MEDIA, MAX_ENTRIES, OciClient, TREE_MEDIA, TREE_SIG_MEDIA,
    buffer_free, get_memory, get_signed, parse_manifest, sha256_hex, url,
};
use crate::util::bpm_tree::{TreePublication, tree_parse};
use crate::util::crypto_openssl::{Cert, cert_free, cert_read_fd, cert_read_file, verify_detached};

/// A signed payload: the bytes and the signature as the caller holds
/// them, NULL pointers included, which `verify_detached()` refuses.
pub(super) struct Signed {
    pub payload: *const u8,
    pub payload_len: usize,
    pub sig: *const u8,
    pub sig_len: usize,
}

/// 0 when `s` verifies against the certificate `read` fills, -EINVAL when
/// there is none.
fn verify_with(s: &Signed, read: impl FnOnce(&mut Cert) -> c_int) -> c_int {
    let mut cert = Cert::new();
    let mut ret = -EINVAL;

    if read(&mut cert) == 0 {
        // SAFETY: the payload and signature as the caller lends them,
        // and the cert just read.
        ret = unsafe { verify_detached(s.payload, s.payload_len, s.sig, s.sig_len, &cert) };
    }
    // SAFETY: a cert read or left empty, freed once.
    unsafe { cert_free(&mut cert) };
    ret
}

/// Against the certificate in the file at `cert_path`.
pub(super) fn verify_cms(s: &Signed, cert_path: *const c_char) -> c_int {
    // SAFETY: cert_read_file() takes the caller's path as it is.
    verify_with(s, |cert| unsafe { cert_read_file(cert_path, cert) })
}

/// Against the certificate the open `cert_fd` reads.
pub(super) fn verify_cms_fd(s: &Signed, cert_fd: c_int) -> c_int {
    // SAFETY: an fd and a cert to fill.
    verify_with(s, |cert| unsafe { cert_read_fd(cert_fd, cert) })
}

/// What a tree fetch holds until it ends.
struct Fetch {
    manifest: BpmBuffer,
    payload: BpmBuffer,
    sig: BpmBuffer,
    layers: *mut Descriptor,
}

impl Drop for Fetch {
    fn drop(&mut self) {
        // SAFETY: NULL, or the MAX_ENTRIES descriptors xcalloc() gave.
        unsafe { xfree(self.layers.cast(), MAX_ENTRIES * size_of::<Descriptor>()) };
        buffer_free(&mut self.manifest);
        buffer_free(&mut self.payload);
        buffer_free(&mut self.sig);
    }
}

/// The signed tree publication at `repository:reference`, every layer
/// checked against its descriptor and the payload against `cert_path`,
/// parsed into `publication`, and the manifest's digest. -ENOENT when the
/// reference does not exist yet.
pub(super) fn fetch_publication(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    cert_path: *const c_char,
    publication: *mut TreePublication,
    manifest_digest: &mut [u8],
) -> c_int {
    let mut manifest_url = [0u8; PATH_MAX];
    let mut hex = [0u8; 65];
    let mut nl = 0;

    if reference.is_empty()
        || reference.iter().any(|&ch| matches!(ch, b'/' | b'?' | b'#'))
        || contains(reference, b"..")
    {
        return -EINVAL;
    }
    let ret = url(c, repository, b"manifests", reference, &mut manifest_url);
    if ret != 0 {
        return ret;
    }
    let Ok(manifest_url) = CStr::from_bytes_until_nul(&manifest_url) else {
        return -EINVAL;
    };
    let mut f = Fetch {
        manifest: BpmBuffer::new(),
        payload: BpmBuffer::new(),
        sig: BpmBuffer::new(),
        layers: ptr::null_mut(),
    };
    let ret = get_memory(
        c,
        manifest_url,
        Some(MANIFEST_MEDIA),
        &mut f.manifest,
        false,
    );
    if ret != 0 {
        return ret;
    }
    if sha256_hex(f.manifest.data, f.manifest.len, &mut hex) != 0 {
        return -EKEYREJECTED;
    }
    if strsprintf(manifest_digest, &[b"sha256:", cstr(&hex)]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: xcalloc() returns NULL or room for the descriptors, zeroed.
    f.layers = unsafe { xcalloc(MAX_ENTRIES, size_of::<Descriptor>()) }.cast();
    if f.layers.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the manifest's len bytes.
    let manifest = unsafe { ffi::slice(f.manifest.data, f.manifest.len) };
    let ret = parse_manifest(manifest, f.layers, MAX_ENTRIES as c_int, &mut nl, None);
    if ret != 0 {
        return ret;
    }
    // SAFETY: parse_manifest() wrote nl descriptors at layers.
    let layers = unsafe { ffi::slice(f.layers, usize::try_from(nl).unwrap_or(0)) };
    let ret = get_signed(
        c,
        repository,
        layers,
        TREE_MEDIA,
        TREE_SIG_MEDIA,
        &mut f.payload,
        &mut f.sig,
    );
    if ret != 0 {
        return ret;
    }
    let signed = Signed {
        payload: f.payload.data,
        payload_len: f.payload.len,
        sig: f.sig.data,
        sig_len: f.sig.len,
    };
    if verify_cms(&signed, cert_path) != 0 {
        return -EKEYREJECTED;
    }
    // SAFETY: the payload's len bytes, and the caller's publication.
    unsafe { tree_parse(f.payload.data.cast(), f.payload.len, publication) }
}
