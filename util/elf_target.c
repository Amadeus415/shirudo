// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * ELF symbol and GNU build-ID handling for uprobe.multi upatches.
 */

#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf_target.h"
#include "malloc.h"

/*
 * libbpf uses this resolver for its uprobe.multi attach path. It is not yet
 * part of libbpf's installed public headers, so keep the narrow declaration
 * local instead of including libbpf_internal.h (which requires kernel-only
 * headers that are not part of Shirudo's userspace build).
 */
extern int elf_resolve_pattern_offsets(const char *binary_path,
					      const char *pattern,
					      unsigned long **poffsets,
					      size_t *pcnt);

static int u64_cmp(const void *a, const void *b)
{
	uint64_t av = *(const uint64_t *)a;
	uint64_t bv = *(const uint64_t *)b;

	return av > bv ? 1 : av < bv ? -1 : 0;
}

static int note_build_id(Elf_Data *data,
			 uint8_t build_id[SHIRUDO_UPATCH_BUILD_ID_MAX],
			 uint32_t *build_id_len)
{
	size_t off = 0;

	while (off < data->d_size) {
		GElf_Nhdr nhdr;
		size_t name_off, desc_off, next;
		const unsigned char *p = data->d_buf;

		next = gelf_getnote(data, off, &nhdr, &name_off, &desc_off);
		if (!next)
			break;
		if (nhdr.n_type == NT_GNU_BUILD_ID && nhdr.n_namesz >= 3 &&
		    name_off <= data->d_size && nhdr.n_namesz <= data->d_size - name_off &&
		    desc_off <= data->d_size && nhdr.n_descsz <= data->d_size - desc_off &&
		    memcmp(p + name_off, "GNU", 3) == 0) {
			if (!nhdr.n_descsz ||
			    nhdr.n_descsz > SHIRUDO_UPATCH_BUILD_ID_MAX)
				return -E2BIG;
			memcpy(build_id, p + desc_off, nhdr.n_descsz);
			*build_id_len = nhdr.n_descsz;
			return 0;
		}
		if (next <= off)
			break;
		off = next;
	}
	return -ENOENT;
}

static int elf_build_id(Elf *elf,
			uint8_t build_id[SHIRUDO_UPATCH_BUILD_ID_MAX],
			uint32_t *build_id_len)
{
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	size_t i, phnum;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		Elf_Data *data = NULL;

		if (!gelf_getshdr(scn, &shdr))
			return -EINVAL;
		if (shdr.sh_type != SHT_NOTE)
			continue;
		while ((data = elf_getdata(scn, data)) != NULL) {
			int err = note_build_id(data, build_id, build_id_len);

			if (!err || err != -ENOENT)
				return err;
		}
	}

	/* Section headers can be stripped; fall back to PT_NOTE segments. */
	if (!gelf_getehdr(elf, &ehdr) || elf_getphdrnum(elf, &phnum) != 0)
		return -EINVAL;
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		Elf_Data *data;
		int err;

		if (!gelf_getphdr(elf, (int)i, &phdr))
			return -EINVAL;
		if (phdr.p_type != PT_NOTE || !phdr.p_filesz)
			continue;
		data = elf_getdata_rawchunk(elf, phdr.p_offset, phdr.p_filesz,
					    ELF_T_NHDR);
		if (!data)
			return -EINVAL;
		err = note_build_id(data, build_id, build_id_len);
		if (!err || err != -ENOENT)
			return err;
	}
	return -ENOENT;
}

int shirudo_elf_build_id_fd(int fd,
			    uint8_t build_id[SHIRUDO_UPATCH_BUILD_ID_MAX],
			    uint32_t *build_id_len)
{
	Elf *elf;
	int err;

	if (fd < 0 || !build_id || !build_id_len)
		return -EINVAL;
	*build_id_len = 0;
	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EINVAL;
	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		return -EINVAL;
	if (elf_kind(elf) != ELF_K_ELF)
		err = -EINVAL;
	else
		err = elf_build_id(elf, build_id, build_id_len);
	elf_end(elf);
	return err;
}

int shirudo_elf_target_resolve(const char *path, const char *pattern,
			       struct shirudo_elf_target *out)
{
	Elf *elf = NULL;
	unsigned long *resolved_offsets = NULL;
	uint32_t i, unique;
	size_t nr_resolved = 0;
	int fd = -1, err;

	if (!path || path[0] != '/' || !pattern || !pattern[0] || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf || elf_kind(elf) != ELF_K_ELF) {
		err = -EINVAL;
		goto out;
	}
	err = elf_build_id(elf, out->build_id, &out->build_id_len);
	if (err)
		goto out;

	/*
	 * libbpf owns the ELF symbol matching and virtual-address-to-file-offset
	 * conversion used by uprobe.multi. Keep only the build-ID extraction above
	 * in this Shirudo-specific adapter.
	 */
	err = elf_resolve_pattern_offsets(path, pattern,
					  &resolved_offsets, &nr_resolved);
	if (err)
		goto out;
	if (nr_resolved == 0) {
		err = -ENOENT;
		goto out;
	}
	if (nr_resolved > SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX ||
	    nr_resolved > UINT32_MAX) {
		err = -E2BIG;
		goto out;
	}
	out->offsets = xcalloc(nr_resolved, sizeof(*out->offsets));
	if (!out->offsets) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < nr_resolved; i++)
		out->offsets[i] = resolved_offsets[i];
	out->nr_offsets = (uint32_t)nr_resolved;
	shirudo_libc_free(resolved_offsets);
	resolved_offsets = NULL;

	qsort(out->offsets, out->nr_offsets, sizeof(*out->offsets), u64_cmp);
	for (i = 1, unique = 1; i < out->nr_offsets; i++) {
		if (out->offsets[i] != out->offsets[unique - 1])
			out->offsets[unique++] = out->offsets[i];
	}
	out->nr_offsets = unique;
	err = 0;
out:
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	shirudo_libc_free(resolved_offsets);
	if (err)
		shirudo_elf_target_free(out);
	return err;
}

void shirudo_elf_target_free(struct shirudo_elf_target *target)
{
	if (!target)
		return;
	xfree(target->offsets,
	      (size_t)target->nr_offsets * sizeof(*target->offsets));
	memset(target, 0, sizeof(*target));
}
