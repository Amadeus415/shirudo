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

static bool glob_match(const char *str, const char *pat)
{
	while (*str && *pat && *pat != '*') {
		if (*pat == '?') {
			str++;
			pat++;
			continue;
		}
		if (*str != *pat)
			return false;
		str++;
		pat++;
	}
	if (*pat == '*') {
		while (*pat == '*')
			pat++;
		if (!*pat)
			return true;
		while (*str) {
			if (glob_match(str, pat))
				return true;
			str++;
		}
	}
	return !*str && !*pat;
}

static int u64_cmp(const void *a, const void *b)
{
	uint64_t av = *(const uint64_t *)a;
	uint64_t bv = *(const uint64_t *)b;

	return av > bv ? 1 : av < bv ? -1 : 0;
}

static int append_offset(uint64_t **offsets, uint32_t *nr, uint32_t *cap,
			 uint64_t offset)
{
	uint64_t *grown;
	uint32_t next;

	if (*nr == SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX)
		return -E2BIG;
	if (*nr < *cap) {
		(*offsets)[(*nr)++] = offset;
		return 0;
	}
	next = *cap ? *cap * 2 : 16;
	if (next > SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX || next < *cap)
		next = SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX;
	grown = xreallocarray(*offsets, *cap, next, sizeof(**offsets));
	if (!grown)
		return -ENOMEM;
	*offsets = grown;
	*cap = next;
	(*offsets)[(*nr)++] = offset;
	return 0;
}

static int resolve_symtab(Elf *elf, unsigned int sh_type,
			  const char *pattern, uint64_t **offsets,
			  uint32_t *nr, uint32_t *cap)
{
	Elf_Scn *scn = NULL;
	bool found_table = false;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		Elf_Data *data = NULL;
		size_t i, nr_syms;

		if (!gelf_getshdr(scn, &shdr))
			return -EINVAL;
		if (shdr.sh_type != sh_type)
			continue;
		found_table = true;
		if (!shdr.sh_entsize)
			return -EINVAL;
		while ((data = elf_getdata(scn, data)) != NULL) {
			nr_syms = data->d_size / shdr.sh_entsize;
			for (i = 0; i < nr_syms; i++) {
				GElf_Shdr target_shdr;
				GElf_Sym sym;
				Elf_Scn *target_scn;
				const char *name;
				uint64_t offset;
				int err;

				if (!gelf_getsym(data, (int)i, &sym))
					continue;
				if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
					continue;
				name = elf_strptr(elf, shdr.sh_link, sym.st_name);
				if (!name || !glob_match(name, pattern))
					continue;
				if (sym.st_shndx == SHN_UNDEF ||
				    sym.st_shndx >= SHN_LORESERVE)
					continue;
				target_scn = elf_getscn(elf, sym.st_shndx);
				if (!target_scn ||
				    !gelf_getshdr(target_scn, &target_shdr))
					continue;
				if (sym.st_value < target_shdr.sh_addr)
					continue;
				offset = sym.st_value - target_shdr.sh_addr +
					 target_shdr.sh_offset;
				err = append_offset(offsets, nr, cap, offset);
				if (err)
					return err;
			}
		}
	}
	return found_table ? 0 : -ENOENT;
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
	uint64_t *offsets = NULL;
	uint32_t nr = 0, cap = 0, i, unique;
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
	err = resolve_symtab(elf, SHT_SYMTAB, pattern, &offsets, &nr, &cap);
	if (err && err != -ENOENT)
		goto out;
	if (!nr) {
		err = resolve_symtab(elf, SHT_DYNSYM, pattern,
				     &offsets, &nr, &cap);
		if (err && err != -ENOENT)
			goto out;
	}
	if (!nr) {
		err = -ENOENT;
		goto out;
	}
	qsort(offsets, nr, sizeof(*offsets), u64_cmp);
	for (i = 1, unique = 1; i < nr; i++) {
		if (offsets[i] != offsets[unique - 1])
			offsets[unique++] = offsets[i];
	}
	if (unique != nr) {
		uint64_t *deduped = xreallocarray(offsets, cap, unique,
						   sizeof(*offsets));

		if (deduped)
			offsets = deduped;
		cap = unique;
		nr = unique;
	}
	out->offsets = offsets;
	out->nr_offsets = nr;
	offsets = NULL;
	err = 0;
out:
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	xfree(offsets, (size_t)cap * sizeof(*offsets));
	if (err)
		memset(out, 0, sizeof(*out));
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
