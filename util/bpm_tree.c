/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

#include "bpm_tree.h"
#include "config.h"
#include "io.h"
#include "json.h"
#include "kernel_release.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"
#include "tpm.h"

/* The tree payload is deliberately parsed here instead of through the
 * schema parser: selectors contain maps whose keys are not known ahead of
 * time.  The parser is still bounded and ignores unknown fields. */
struct tree_parser {
	const char *p;
	const char *end;
	unsigned depth;
};

static int tree_mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	char *p;

	if (!path || strlen(path) >= sizeof(tmp))
		return -ENAMETOOLONG;
	strcpy(tmp, path);
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(tmp, mode) && errno != EEXIST)
		return -errno;
	return 0;
}

static void tp_ws(struct tree_parser *p)
{
	while (p->p < p->end && isspace((unsigned char)*p->p))
		p->p++;
}

static int tp_char(struct tree_parser *p, char c)
{
	tp_ws(p);
	if (p->p >= p->end || *p->p != c)
		return -EINVAL;
	p->p++;
	return 0;
}

static int tp_string(struct tree_parser *p, char *out, size_t cap)
{
	size_t n = 0;

	tp_ws(p);
	if (p->p >= p->end || *p->p++ != '"')
		return -EINVAL;
	while (p->p < p->end) {
		unsigned char c = (unsigned char)*p->p++;

		if (c == '"') {
			if (cap)
				out[n < cap ? n : cap - 1] = '\0';
			return n < cap ? 0 : -ENOSPC;
		}
		if (c == '\\') {
			if (p->p >= p->end)
				return -EINVAL;
			c = (unsigned char)*p->p++;
			switch (c) {
			case '"': case '\\': case '/': break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			default: return -EINVAL;
			}
		}
		if (c < 0x20)
			return -EINVAL;
		if (n + 1 < cap)
			out[n] = (char)c;
		n++;
	}
	return -EINVAL;
}

static int tp_skip(struct tree_parser *p)
{
	char scratch[SHIRUDO_TREE_STRING_MAX];

	tp_ws(p);
	if (p->p >= p->end)
		return -EINVAL;
	if (*p->p == '"')
		return tp_string(p, scratch, sizeof(scratch));
	if (*p->p == '{' || *p->p == '[') {
		char open = *p->p++, close = open == '{' ? '}' : ']';
		if (++p->depth > 32)
			return -E2BIG;
		for (;;) {
			tp_ws(p);
			if (p->p >= p->end)
				return -EINVAL;
			if (*p->p == close) {
				p->p++;
				p->depth--;
				return 0;
			}
			if (open == '{') {
				if (tp_string(p, scratch, sizeof(scratch)) ||
				    tp_char(p, ':'))
					return -EINVAL;
			}
			if (tp_skip(p))
				return -EINVAL;
			tp_ws(p);
			if (p->p < p->end && *p->p == ',') {
				p->p++;
				continue;
			}
			if (p->p < p->end && *p->p == close)
				continue;
			return -EINVAL;
		}
	}
	if (*p->p == '-' || isdigit((unsigned char)*p->p)) {
		if (*p->p == '-')
			p->p++;
		while (p->p < p->end && isdigit((unsigned char)*p->p))
			p->p++;
		if (p->p < p->end && *p->p == '.') {
			p->p++;
			while (p->p < p->end && isdigit((unsigned char)*p->p))
				p->p++;
		}
		return 0;
	}
	if ((size_t)(p->end - p->p) >= 4 && !strncmp(p->p, "true", 4)) {
		p->p += 4;
		return 0;
	}
	if ((size_t)(p->end - p->p) >= 5 && !strncmp(p->p, "false", 5)) {
		p->p += 5;
		return 0;
	}
	if ((size_t)(p->end - p->p) >= 4 && !strncmp(p->p, "null", 4)) {
		p->p += 4;
		return 0;
	}
	return -EINVAL;
}

static int tp_int(struct tree_parser *p, int64_t *out)
{
	char *end;
	long long v;

	tp_ws(p);
	v = strtoll(p->p, &end, 10);
	if (end == p->p || end > p->end)
		return -EINVAL;
	p->p = end;
	*out = (int64_t)v;
	return 0;
}

static int tp_key(struct tree_parser *p, char *key, size_t cap, bool *first)
{
	tp_ws(p);
	if (!*first) {
		if (tp_char(p, ','))
			return -EINVAL;
	}
	*first = false;
	if (tp_string(p, key, cap) || tp_char(p, ':'))
		return -EINVAL;
	return 0;
}

static int kv_add(struct shirudo_tree_kv *dst, int *n, int max,
			  const char *key, const char *value)
{
	if (*n >= max)
		return -E2BIG;
	if (strlen(key) >= sizeof(dst[0].key) ||
	    strlen(value) >= sizeof(dst[0].value))
		return -ENOSPC;
	strcpy(dst[*n].key, key);
	strcpy(dst[*n].value, value);
	(*n)++;
	return 0;
}

static int tp_string_array(struct tree_parser *p,
			   char values[][SHIRUDO_TREE_STRING_MAX], int *n, int max)
{
	int count = 0;

	if (tp_char(p, '['))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == ']') {
			p->p++;
			if (!count)
				return -EINVAL;
			*n = count;
			return 0;
		}
		if (count >= max || tp_string(p, values[count],
					       SHIRUDO_TREE_STRING_MAX))
			return count >= max ? -E2BIG : -EINVAL;
		count++;
		tp_ws(p);
		if (p->p >= p->end)
			return -EINVAL;
		if (*p->p == ',') {
			p->p++;
			continue;
		}
		if (*p->p != ']')
			return -EINVAL;
	}
}

static int tp_selector_string_map(struct tree_parser *p,
				  struct shirudo_tree_selector_kv *dst,
				  int *n, int max)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		int values = 0;

		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first) || *n >= max ||
		    tp_string_array(p, dst[*n].values, &values,
					SHIRUDO_TREE_MAX_SELECTOR_VALUES))
			return -EINVAL;
		strcpy(dst[*n].key, key);
		dst[*n].n_values = values;
		(*n)++;
	}
}

static int tp_selector(struct tree_parser *p, struct shirudo_tree_selector *s)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first))
			return -EINVAL;
		if (!strcmp(key, "kernel_release_prefix")) {
			if (tp_string_array(p, s->kernel_release_prefix,
					    &s->n_kernel_release_prefix,
					    SHIRUDO_TREE_MAX_SELECTOR_VALUES))
				return -EINVAL;
		} else if (!strcmp(key, "architecture")) {
			if (tp_string_array(p, s->architecture,
					    &s->n_architecture,
					    SHIRUDO_TREE_MAX_SELECTOR_VALUES))
				return -EINVAL;
		} else if (!strcmp(key, "kconfig") ||
				   !strcmp(key, "kernel_config")) {
			if (tp_selector_string_map(p, s->kconfig, &s->n_kconfig,
						SHIRUDO_TREE_MAX_KCONFIG))
				return -EINVAL;
		} else if (!strcmp(key, "labels")) {
			if (tp_selector_string_map(p, s->labels, &s->n_labels,
						SHIRUDO_TREE_MAX_LABELS))
				return -EINVAL;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

static int tp_artifact(struct tree_parser *p, struct shirudo_tree_artifact *a)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first))
			return -EINVAL;
		if (!strcmp(key, "repository")) {
			if (tp_string(p, a->repository, sizeof(a->repository)))
				return -EINVAL;
		} else if (!strcmp(key, "manifest_digest")) {
			if (tp_string(p, a->manifest_digest,
				      sizeof(a->manifest_digest)))
				return -EINVAL;
		} else if (!strcmp(key, "layer_digest")) {
			if (tp_string(p, a->layer_digest, sizeof(a->layer_digest)))
				return -EINVAL;
		} else if (!strcmp(key, "payload_sha256")) {
			if (tp_string(p, a->payload_sha256,
				      sizeof(a->payload_sha256)))
				return -EINVAL;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

static int tp_operation(struct tree_parser *p, struct shirudo_tree_operation *o)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			if (!o->id[0] || !o->op[0] || o->seq <= 0 ||
			    !o->operation_digest[0] || !o->artifact.repository[0] ||
			    !o->artifact.manifest_digest[0] ||
			    !o->artifact.layer_digest[0] ||
			    !o->artifact.payload_sha256[0])
				return -EINVAL;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first))
			return -EINVAL;
		if (!strcmp(key, "seq")) {
			if (tp_int(p, &o->seq)) return -EINVAL;
		} else if (!strcmp(key, "op")) {
			if (tp_string(p, o->op, sizeof(o->op))) return -EINVAL;
		} else if (!strcmp(key, "id")) {
			if (tp_string(p, o->id, sizeof(o->id))) return -EINVAL;
		} else if (!strcmp(key, "selector")) {
			if (tp_selector(p, &o->selector)) return -EINVAL;
		} else if (!strcmp(key, "artifact")) {
			if (tp_artifact(p, &o->artifact)) return -EINVAL;
		} else if (!strcmp(key, "expected_payload_sha256")) {
			if (tp_string(p, o->expected_payload_sha256,
				      sizeof(o->expected_payload_sha256)))
				return -EINVAL;
		} else if (!strcmp(key, "operation_digest")) {
			if (tp_string(p, o->operation_digest,
				      sizeof(o->operation_digest)))
				return -EINVAL;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

void shirudo_tree_publication_free(struct shirudo_tree_publication *pub)
{
	if (!pub)
		return;
	if (pub->operations)
		xfree(pub->operations,
		      (size_t)pub->operations_capacity * sizeof(*pub->operations));
	*pub = (struct shirudo_tree_publication){};
}

int shirudo_tree_parse(const char *body, size_t len,
			       struct shirudo_tree_publication *out)
{
	struct tree_parser p;
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;
	bool seen_schema = false, seen_generation = false;
	bool seen_base = false, seen_base_seq = false;
	bool seen_operations = false, seen_head = false, seen_head_seq = false;
	int64_t schema = 0;

	if (!body || !out || len > SHIRUDO_JSON_MAX_BYTES)
		return -EINVAL;
	p = (struct tree_parser){ .p = body, .end = body + len };
	*out = (struct shirudo_tree_publication){};
	#define TREE_PARSE_FAIL(err) do { \
		shirudo_tree_publication_free(out); \
		return (err); \
	} while (0)
	if (tp_char(&p, '{')) TREE_PARSE_FAIL(-EINVAL);
	for (;;) {
		tp_ws(&p);
		if (p.p < p.end && *p.p == '}') {
			p.p++;
			break;
		}
		if (tp_key(&p, key, sizeof(key), &first)) TREE_PARSE_FAIL(-EINVAL);
		if (!strcmp(key, "schema")) {
			if (tp_int(&p, &schema)) TREE_PARSE_FAIL(-EINVAL);
			seen_schema = true;
		} else if (!strcmp(key, "tree_id")) {
			if (tp_string(&p, out->tree_id, sizeof(out->tree_id))) TREE_PARSE_FAIL(-EINVAL);
		} else if (!strcmp(key, "generation")) {
			if (tp_int(&p, &out->generation)) TREE_PARSE_FAIL(-EINVAL);
			seen_generation = true;
		} else if (!strcmp(key, "parent_manifest_digest")) {
			if (tp_string(&p, out->parent_manifest_digest,
				      sizeof(out->parent_manifest_digest))) TREE_PARSE_FAIL(-EINVAL);
		} else if (!strcmp(key, "base")) {
			seen_base = true;
			if (tp_char(&p, '{')) TREE_PARSE_FAIL(-EINVAL);
			{
				bool bf = true;
				for (;;) {
					tp_ws(&p);
					if (p.p < p.end && *p.p == '}') { p.p++; break; }
					if (tp_key(&p, key, sizeof(key), &bf)) TREE_PARSE_FAIL(-EINVAL);
					if (!strcmp(key, "seq")) {
						if (tp_int(&p, &out->base_seq)) TREE_PARSE_FAIL(-EINVAL);
						seen_base_seq = true;
					} else if (tp_skip(&p)) TREE_PARSE_FAIL(-EINVAL);
				}
			}
		} else if (!strcmp(key, "operations")) {
			seen_operations = true;
			if (tp_char(&p, '[')) TREE_PARSE_FAIL(-EINVAL);
			for (;;) {
				tp_ws(&p);
				if (p.p < p.end && *p.p == ']') { p.p++; break; }
				if (out->n_operations >= SHIRUDO_TREE_MAX_OPS)
					TREE_PARSE_FAIL(-E2BIG);
				if (out->n_operations >= out->operations_capacity) {
					int old_capacity = out->operations_capacity;
					int new_capacity = old_capacity ? old_capacity * 2 : 16;
					struct shirudo_tree_operation *operations;
					if (new_capacity > SHIRUDO_TREE_MAX_OPS)
						new_capacity = SHIRUDO_TREE_MAX_OPS;
					operations = xreallocarray(out->operations,
								   (size_t)old_capacity,
								   (size_t)new_capacity,
								   sizeof(*operations));
					if (!operations)
						TREE_PARSE_FAIL(-ENOMEM);
					out->operations = operations;
					out->operations_capacity = new_capacity;
				}
				if (tp_operation(&p, &out->operations[out->n_operations]))
					TREE_PARSE_FAIL(-EINVAL);
				out->n_operations++;
				tp_ws(&p);
				if (p.p < p.end && *p.p == ',') { p.p++; continue; }
				if (p.p < p.end && *p.p == ']') { p.p++; break; }
				TREE_PARSE_FAIL(-EINVAL);
			}
		} else if (!strcmp(key, "head")) {
			seen_head = true;
			if (tp_char(&p, '{')) TREE_PARSE_FAIL(-EINVAL);
			{
				bool hf = true;
				for (;;) {
					tp_ws(&p);
					if (p.p < p.end && *p.p == '}') { p.p++; break; }
					if (tp_key(&p, key, sizeof(key), &hf)) TREE_PARSE_FAIL(-EINVAL);
					if (!strcmp(key, "seq")) {
						if (tp_int(&p, &out->head_seq)) TREE_PARSE_FAIL(-EINVAL);
						seen_head_seq = true;
					} else if (tp_skip(&p)) TREE_PARSE_FAIL(-EINVAL);
				}
			}
		} else if (tp_skip(&p)) TREE_PARSE_FAIL(-EINVAL);
		tp_ws(&p);
		if (p.p < p.end && *p.p == '}') { p.p++; break; }
		if (p.p >= p.end) TREE_PARSE_FAIL(-EINVAL);
	}
	tp_ws(&p);
	if (p.p != p.end || !seen_schema || !seen_generation || !seen_base ||
	    !seen_base_seq || !seen_operations || !seen_head || !seen_head_seq ||
	    schema != 2 || !out->tree_id[0] ||
	    out->generation < 0 || out->base_seq < 0 || out->head_seq < out->base_seq)
		TREE_PARSE_FAIL(-EINVAL);
	for (int i = 0; i < out->n_operations; i++) {
		if (i && out->operations[i].seq != out->operations[i - 1].seq + 1)
			TREE_PARSE_FAIL(-EINVAL);
	}
	#undef TREE_PARSE_FAIL
	return 0;
}

static const char *kv_value(const struct shirudo_tree_kv *v, int n,
				 const char *key)
{
	for (int i = 0; i < n; i++)
		if (!strcmp(v[i].key, key))
			return v[i].value;
	return NULL;
}

static int selector_values_match(const struct shirudo_tree_selector_kv *v,
					 const char *want)
{
	if (!v || !want)
		return 0;
	for (int i = 0; i < v->n_values; i++)
		if (!strcmp(v->values[i], want))
			return 1;
	return 0;
}

static int read_config_file(const char *path, struct shirudo_tree_kv *out,
				int *n, int max, bool gz)
{
	char line[512];
	int rc = 0;
	*n = 0;
	if (gz) {
		gzFile f = gzopen(path, "rb");
		if (!f) return -errno;
		while (gzgets(f, line, sizeof(line))) {
			char *eq, *key, *value;
			if (line[0] == '#' && !strncmp(line, "# CONFIG_", 9)) {
				key = line + 2; eq = strstr(key, " is not set");
				if (eq) { *eq = '\0'; rc = kv_add(out, n, max, key, "n"); }
			} else if ((eq = strchr(line, '='))) {
				*eq++ = '\0'; key = line; value = eq;
				value[strcspn(value, "\r\n")] = '\0';
				if (value[0] == '"') {
					size_t l = strlen(value);
					if (l > 1 && value[l - 1] == '"') { value[l - 1] = '\0'; value++; }
				}
				rc = kv_add(out, n, max, key, value);
			}
			if (rc) break;
		}
		gzclose(f);
		return rc;
	}
	{
		FILE *f = fopen(path, "r");
		if (!f) return -errno;
		while (fgets(line, sizeof(line), f)) {
			char *start = line, *end, *eq;
			while (*start && isspace((unsigned char)*start)) start++;
			if (*start == '#' || *start == '\0') continue;
			end = start + strlen(start);
			while (end > start && isspace((unsigned char)end[-1])) *--end = '\0';
			eq = strchr(start, '=');
			if (!eq) continue;
			*eq++ = '\0';
			end = eq + strlen(eq);
			while (end > eq && isspace((unsigned char)end[-1])) *--end = '\0';
			while (*eq && isspace((unsigned char)*eq)) eq++;
			rc = kv_add(out, n, max, start, eq);
			if (rc) break;
		}
		fclose(f);
	}
	return rc;
}

/* The kernel config can contain thousands of entries.  Index only the
 * selector keys, then scan the complete config once and retain matching
 * values.  This avoids both an arbitrary config-entry cap and an O(N*M)
 * lookup for N config entries and M selector keys. */
#define SHIRUDO_TREE_SELECTOR_HASH_SIZE 128

static unsigned int selector_hash(const char *key)
{
	uint32_t hash = 2166136261u;

	for (; *key; key++)
		hash = (hash ^ (unsigned char)*key) * 16777619u;
	return hash;
}

static void selector_hash_build(const struct shirudo_tree_selector *s,
				       int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE])
{
	memset(slots, 0xff, sizeof(int) * SHIRUDO_TREE_SELECTOR_HASH_SIZE);
	for (int i = 0; i < s->n_kconfig; i++) {
		unsigned int slot = selector_hash(s->kconfig[i].key) &
			(SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1);

		while (slots[slot] >= 0 &&
		       strcmp(s->kconfig[slots[slot]].key, s->kconfig[i].key))
			slot = (slot + 1) & (SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1);
		if (slots[slot] < 0)
			slots[slot] = i;
	}
}

static int selector_hash_find(const struct shirudo_tree_selector *s,
				      const int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE],
				      const char *key)
{
	unsigned int slot = selector_hash(key) &
		(SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1);

	for (int probes = 0; probes < SHIRUDO_TREE_SELECTOR_HASH_SIZE;
	     probes++, slot = (slot + 1) &
			(SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1)) {
		if (slots[slot] < 0)
			return -1;
		if (!strcmp(s->kconfig[slots[slot]].key, key))
			return slots[slot];
	}
	return -1;
}

static int selector_config_line(const char *line,
				const struct shirudo_tree_selector *s,
				const int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE],
				char values[][SHIRUDO_TREE_STRING_MAX],
				bool found[])
{
	char copy[1024], *start, *eq, *end, *value;
	int index;

	if (strlen(line) >= sizeof(copy))
		return 0;
	strcpy(copy, line);
	start = copy;
	while (*start && isspace((unsigned char)*start))
		start++;
	if (!*start)
		return 0;

	if (!strncmp(start, "# CONFIG_", 9)) {
		start += 2;
		eq = strstr(start, " is not set");
		if (!eq)
			return 0;
		*eq = '\0';
		value = "n";
	} else {
		if (*start == '#')
			return 0;
		eq = strchr(start, '=');
		if (!eq)
			return 0;
		*eq++ = '\0';
		end = start + strlen(start);
		while (end > start && isspace((unsigned char)end[-1]))
			*--end = '\0';
		while (*eq && isspace((unsigned char)*eq))
			eq++;
		end = eq + strlen(eq);
		while (end > eq && isspace((unsigned char)end[-1]))
			*--end = '\0';
		value = eq;
		if (value[0] == '"') {
			size_t len = strlen(value);

			if (len > 1 && value[len - 1] == '"') {
				value[len - 1] = '\0';
				value++;
			}
		}
	}

	index = selector_hash_find(s, slots, start);
	if (index < 0)
		return 0;
	if (strlen(value) >= SHIRUDO_TREE_STRING_MAX)
		return -ENOSPC;
	strcpy(values[index], value);
	found[index] = true;
	return 0;
}

static int read_selector_config_file(const char *path,
					 const struct shirudo_tree_selector *s,
					 const int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE],
					 char values[][SHIRUDO_TREE_STRING_MAX],
					 bool found[], bool gz)
{
	char line[1024];
	int rc = 0;

	if (gz) {
		gzFile f = gzopen(path, "rb");

		if (!f)
			return -errno;
		while (gzgets(f, line, sizeof(line))) {
			rc = selector_config_line(line, s, slots, values, found);
			if (rc)
				break;
		}
		if (!rc && gzclose(f) != Z_OK)
			rc = -EIO;
		else if (rc)
			gzclose(f);
		return rc;
	}

	{
		FILE *f = fopen(path, "r");

		if (!f)
			return -errno;
		while (fgets(line, sizeof(line), f)) {
			rc = selector_config_line(line, s, slots, values, found);
			if (rc)
				break;
		}
		if (!rc && ferror(f))
			rc = errno ? -errno : -EIO;
		fclose(f);
	}
	return rc;
}

int shirudo_tree_selector_matches(const struct shirudo_tree_selector *s)
{
	struct utsname u;
	struct shirudo_tree_kv labels[SHIRUDO_TREE_MAX_LABELS];
	char cfg_values[SHIRUDO_TREE_MAX_KCONFIG][SHIRUDO_TREE_STRING_MAX];
	int cfg_slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE];
	bool cfg_found[SHIRUDO_TREE_MAX_KCONFIG] = {};
	int nl = 0, config_rc;
	const char *v;
	char path[PATH_MAX];
	bool matched, config_any;

	/* An empty selector is the tree's explicit wildcard.  Evaluate this
	 * before consulting node metadata so an unconstrained operation is
	 * still applicable if uname(2) is unavailable. */
	if (!s)
		return 0;
	if (!s->n_kernel_release_prefix && !s->n_architecture &&
	    !s->n_kconfig && !s->n_labels)
		return 1;
	if (uname(&u) != 0)
		return 0;
	if (s->n_kernel_release_prefix) {
		matched = false;
		for (int i = 0; i < s->n_kernel_release_prefix; i++)
			if (shirudo_kernel_release_prefix_matches(u.release,
							   s->kernel_release_prefix[i])) {
				matched = true;
				break;
			}
		if (!matched)
			return 0;
	}
	if (s->n_architecture) {
		matched = false;
		for (int i = 0; i < s->n_architecture; i++)
			if (!strcmp(u.machine, s->architecture[i])) {
				matched = true;
				break;
			}
		if (!matched)
			return 0;
	}
	if (s->n_kconfig) {
		selector_hash_build(s, cfg_slots);
		config_rc = read_selector_config_file("/proc/config.gz", s,
						      cfg_slots, cfg_values, cfg_found,
						      true);
		config_any = false;
		for (int i = 0; i < s->n_kconfig; i++)
			if (cfg_found[i])
				config_any = true;
		if (config_rc || !config_any) {
			memset(cfg_found, 0, sizeof(cfg_found));
			snprintf(path, sizeof(path), "/boot/config-%s", u.release);
			if (read_selector_config_file(path, s, cfg_slots, cfg_values,
						       cfg_found, false))
				return 0;
		}
		for (int i = 0; i < s->n_kconfig; i++) {
			if (!cfg_found[i] ||
			    !selector_values_match(&s->kconfig[i], cfg_values[i]))
				return 0;
		}
	}
	if (s->n_labels) {
		if (read_config_file("/etc/shirudo/node.labels", labels, &nl,
				     ARRAY_SIZE(labels), false))
			return 0;
		for (int i = 0; i < s->n_labels; i++) {
			v = kv_value(labels, nl, s->labels[i].key);
			if (!v || !selector_values_match(&s->labels[i], v))
				return 0;
		}
	}
	return 1;
}

static int tree_read_file(const char *path, unsigned char **body, size_t *len)
{
	struct stat st;
	unsigned char *p;
	ssize_t got;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -errno;
	if (fstat(fd, &st) || st.st_size < 0 || st.st_size > SHIRUDO_JSON_MAX_BYTES) {
		close(fd); return -E2BIG;
	}
	p = xmalloc((size_t)st.st_size + 1);
	if (!p) { close(fd); return -ENOMEM; }
	got = read(fd, p, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size) { xfree(p, (size_t)st.st_size + 1); return -EIO; }
	p[got] = '\0'; *body = p; *len = (size_t)got;
	return 0;
}

int shirudo_tree_state_read(struct shirudo_tree_state *out)
{
	unsigned char *body;
	size_t len;
	int64_t schema = 0;
	struct shirudo_json_field f[] = {
		{ "schema", SHIRUDO_JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "tree_id", SHIRUDO_JSON_T_STRING, out->tree_id,
		  sizeof(out->tree_id), 0, NULL, 0 },
		{ "generation", SHIRUDO_JSON_T_INT, &out->generation, 0, 0, NULL, 0 },
		{ "last_seq", SHIRUDO_JSON_T_INT, &out->last_seq, 0, 0, NULL, 0 },
		{ "projection_root", SHIRUDO_JSON_T_STRING, out->projection_root,
		  sizeof(out->projection_root), 0, NULL, 0 },
		{ "projection_root_tpm", SHIRUDO_JSON_T_STRING,
		  out->projection_root_tpm, sizeof(out->projection_root_tpm), 0, NULL, 0 },
		{ "manifest_digest", SHIRUDO_JSON_T_STRING, out->manifest_digest,
		  sizeof(out->manifest_digest), 0, NULL, 0 },
	};
	int rc;

	*out = (struct shirudo_tree_state){};
	rc = tree_read_file(SHIRUDO_BPM_TREE_STATE_PATH, &body, &len);
	if (rc) return rc;
	rc = shirudo_json_parse((const char *)body, len, f, ARRAY_SIZE(f));
	if (!rc && (schema != 1 || !f[1].seen || !f[3].seen || !f[4].seen))
		rc = -EINVAL;
	if (!rc && !f[5].seen) {
		/* State written before the software projection field was added. */
		memcpy(out->projection_root, out->projection_root_tpm,
		       sizeof(out->projection_root));
	}
	if (!rc && (strlen(out->projection_root) != 64 ||
		    shirudo_hex_decode(out->projection_root, (uint8_t[32]){}, 32) ||
		    (out->projection_root_tpm[0] &&
		     (strlen(out->projection_root_tpm) != 64 ||
		      shirudo_hex_decode(out->projection_root_tpm, (uint8_t[32]){}, 32)))))
		rc = -EINVAL;
	if (!rc && out->manifest_digest[0] &&
	    (strlen(out->manifest_digest) != 71 ||
	     strncmp(out->manifest_digest, "sha256:", 7) ||
	     shirudo_hex_decode(out->manifest_digest + 7, (uint8_t[32]){}, 32)))
		rc = -EINVAL;
	out->schema = (int)schema;
	xfree(body, len + 1);
	return rc;
}

static int tree_atomic_write(const char *path, const void *data, size_t len)
{
	char tmp[PATH_MAX];
	char dir[PATH_MAX];
	const char *slash = strrchr(path, '/');
	int fd, dirfd = -1, rc;
	if (!slash || (size_t)(slash - path) >= sizeof(dir)) return -EINVAL;
	memcpy(dir, path, slash - path); dir[slash - path] = '\0';
	{
		int mkdir_rc = tree_mkdir_p(dir, 0700);
		if (mkdir_rc) {
			pr_err("tree state mkdir %s rc=%d errno=%d", dir, mkdir_rc, errno);
			return mkdir_rc;
		}
	}
	if (snprintf(tmp, sizeof(tmp), "%s/.tmp.%ld", dir, (long)getpid()) >= (int)sizeof(tmp)) return -ENAMETOOLONG;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) return -errno;
	rc = shirudo_write_all(fd, data, len);
	if (!rc && fsync(fd)) rc = -errno;
	if (close(fd) && !rc) rc = -errno;
	if (!rc && rename(tmp, path)) rc = -errno;
	if (!rc) {
		dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dirfd < 0)
			rc = -errno;
		else if (fsync(dirfd))
			rc = -errno;
		if (dirfd >= 0 && close(dirfd) && !rc)
			rc = -errno;
	}
	if (rc) unlink(tmp);
	if (!rc) (void)shirudo_seal_label(path);
	return rc;
}

int shirudo_tree_state_write(const struct shirudo_tree_state *s)
{
	char buf[4096];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "tree_id", s->tree_id);
	shirudo_json_kv_int(&e, "generation", s->generation);
	shirudo_json_kv_int(&e, "last_seq", s->last_seq);
	shirudo_json_kv_string(&e, "projection_root", s->projection_root);
	shirudo_json_kv_string(&e, "projection_root_tpm", s->projection_root_tpm);
	shirudo_json_kv_string(&e, "manifest_digest", s->manifest_digest);
	shirudo_json_obj_close(&e);
	if (e.err) return e.err;
	return tree_atomic_write(SHIRUDO_BPM_TREE_STATE_PATH, buf, e.len);
}

int shirudo_tree_event_append(int64_t seq, const char *operation_digest,
				      const uint8_t projection_root[32])
{
	char buf[1024], root[65];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	int fd, rc;
	if (!operation_digest || strncmp(operation_digest, "sha256:", 7) ||
	    shirudo_hex_decode(operation_digest + 7, (uint8_t[32]){}, 32))
		return -EINVAL;
	shirudo_hex_encode(projection_root, 32, root);
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_int(&e, "seq", seq);
	shirudo_json_kv_string(&e, "digest", operation_digest);
	shirudo_json_kv_string(&e, "projection_root", root);
	shirudo_json_obj_close(&e);
	if (e.err) return e.err;
	{
		int mkdir_rc = tree_mkdir_p(SHIRUDO_BPM_TREE_VAR_DIR, 0700);
		if (mkdir_rc) return mkdir_rc;
	}
	fd = open(SHIRUDO_BPM_TREE_EVENTLOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0) return -errno;
	rc = shirudo_write_all(fd, buf, e.len);
	if (!rc) rc = shirudo_write_all(fd, "\n", 1);
	if (!rc && fsync(fd)) rc = -errno;
	if (close(fd) && !rc) rc = -errno;
	if (!rc) (void)shirudo_seal_label(SHIRUDO_BPM_TREE_EVENTLOG_PATH);
	return rc;
}

int shirudo_tree_event_replay(uint8_t out[32])
{
	unsigned char *body;
	size_t len;
	char *save, *line;
	uint8_t chain[32] = {};
	int64_t previous_seq = 0;
	int rc = tree_read_file(SHIRUDO_BPM_TREE_EVENTLOG_PATH, &body, &len);
	if (rc) return rc;
	for (line = strtok_r((char *)body, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char digest[128] = {};
		char projection[65] = {};
		int64_t seq = 0;
		struct shirudo_json_field f[] = {
			{ "seq", SHIRUDO_JSON_T_INT, &seq, 0, 0, NULL, 0 },
			{ "digest", SHIRUDO_JSON_T_STRING, digest, sizeof(digest),
			  0, NULL, 0 },
			{ "projection_root", SHIRUDO_JSON_T_STRING, projection,
			  sizeof(projection), 0, NULL, 0 },
		};
		uint8_t d[32], next[64], recorded[32];
		rc = shirudo_json_parse(line, strlen(line), f, ARRAY_SIZE(f));
		if (rc || !f[0].seen || !f[1].seen || !f[2].seen ||
		    seq <= previous_seq || strlen(projection) != 64 ||
		    shirudo_hex_decode(projection, recorded, 32)) {
			rc = -EINVAL;
			break;
		}
		previous_seq = seq;
		if (strncmp(digest, "sha256:", 7) ||
		    shirudo_hex_decode(digest + 7, d, sizeof(d))) {
			rc = -EINVAL;
			break;
		}
		memcpy(next, chain, 32); memcpy(next + 32, d, 32);
		shirudo_sha256(next, sizeof(next), chain);
		if (!shirudo_ct_eq(chain, recorded, 32)) { rc = -EINVAL; break; }
	}
	if (!rc) memcpy(out, chain, 32);
	xfree(body, len + 1);
	return rc;
}

static int tree_chain_auth(uint8_t auth[32])
{
	uint8_t cert[32];
	int rc = shirudo_chain_cert_sha256(cert);
	if (rc) return rc;
	shirudo_chain_auth_value(cert, auth);
	return 0;
}

int shirudo_tree_chain_ensure(void)
{
	struct shirudo_tpm *t = NULL;
	struct shirudo_config cfg = {};
	uint8_t auth[32];
	int rc = tree_chain_auth(auth);
	if (rc) return -ENODEV;
	rc = shirudo_tpm_open(&t);
	if (rc) return -ENODEV;
	(void)shirudo_config_load(&cfg);
	rc = shirudo_tpm_nv_define(t, SHIRUDO_TREE_NV_INDEX, auth,
				   cfg.tpm_owner_auth, cfg.tpm_owner_auth_len);
	shirudo_tpm_close(t);
	return rc;
}

int shirudo_tree_chain_read(uint8_t out[32])
{
	struct shirudo_tpm *t = NULL;
	uint8_t auth[32];
	int rc = tree_chain_auth(auth);
	if (rc || shirudo_tpm_open(&t)) return -ENODEV;
	rc = shirudo_tpm_nv_read(t, SHIRUDO_TREE_NV_INDEX, auth, out);
	shirudo_tpm_close(t);
	return rc ? -ENODEV : 0;
}

int shirudo_tree_chain_extend(const uint8_t operation_digest[32],
				      uint8_t out[32])
{
	struct shirudo_tpm *t = NULL;
	uint8_t auth[32], before[32], actual[32], expected[32];
	int rc = tree_chain_auth(auth);
	if (rc || shirudo_tpm_open(&t)) return -ENODEV;
	rc = shirudo_tpm_nv_read(t, SHIRUDO_TREE_NV_INDEX, auth, before);
	if (!rc) rc = shirudo_tpm_nv_extend(t, SHIRUDO_TREE_NV_INDEX, auth,
					  operation_digest);
	if (!rc) rc = shirudo_tpm_nv_read(t, SHIRUDO_TREE_NV_INDEX, auth, actual);
	shirudo_tpm_close(t);
	if (rc) return -EIO;
	shirudo_sha256_2(before, 32, operation_digest, 32, expected);
	if (!shirudo_ct_eq(actual, expected, 32))
		return -EIO;
	if (out) {
		memcpy(out, actual, 32);
	}
	return 0;
}

void shirudo_tree_emit_status(struct shirudo_json_emit *e)
{
	struct shirudo_tree_state s = {};
	uint8_t live[32], replay[32];
	char hex[65];
	bool configured = access(SHIRUDO_BPM_TREE_ETC_PATH, R_OK) == 0;

	shirudo_json_obj_open_key(e, "upatch_tree");
	shirudo_json_kv_bool(e, "configured", configured);
	shirudo_json_kv_bool(e, "pending", access(SHIRUDO_BPM_TREE_PENDING_PATH,
						R_OK) == 0);
	if (shirudo_tree_state_read(&s) == 0) {
		shirudo_json_kv_string(e, "tree_id", s.tree_id);
		shirudo_json_kv_int(e, "generation", s.generation);
		shirudo_json_kv_int(e, "last_seq", s.last_seq);
		shirudo_json_kv_string(e, "projection_root", s.projection_root);
		shirudo_json_kv_string(e, "manifest_digest", s.manifest_digest);
	} else {
		shirudo_json_kv_null(e, "state");
	}
	if (shirudo_tree_chain_read(live) == 0) {
		shirudo_hex_encode(live, 32, hex);
		shirudo_json_kv_string(e, "live_projection_root_tpm", hex);
		if (shirudo_tree_event_replay(replay) == 0)
			shirudo_json_kv_bool(e, "eventlog_matches_tpm",
					shirudo_ct_eq(live, replay, 32));
		else
			shirudo_json_kv_null(e, "eventlog_matches_tpm");
	} else {
		shirudo_json_kv_null(e, "live_projection_root_tpm");
		shirudo_json_kv_null(e, "eventlog_matches_tpm");
	}
	shirudo_json_obj_close(e);
}
