/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_UTIL_UPATCH_MAPS_OTEL_H
#define SHIRUDO_UTIL_UPATCH_MAPS_OTEL_H

#include <stdbool.h>
#include <stddef.h>

#include "upatch_maps.h"

enum shirudo_otel_signal {
	SHIRUDO_OTEL_LOG,
	SHIRUDO_OTEL_METRIC,
};

enum shirudo_otel_mode {
	SHIRUDO_OTEL_AUTO,
	SHIRUDO_OTEL_FORCE_LOG,
	SHIRUDO_OTEL_FORCE_METRIC,
};

enum shirudo_otel_metric_kind {
	SHIRUDO_OTEL_METRIC_COUNTER,
	SHIRUDO_OTEL_METRIC_GAUGE,
};

struct shirudo_otel_opts {
	const char	*endpoint;
	bool		allow_insecure;
	unsigned int	retries;
	enum shirudo_otel_metric_kind metric_kind;
	bool		metric_kind_set;
	const char	*metric_name;
	const char	*metric_unit;
	const char	*metric_description;
};

int shirudo_upatch_maps_otel_classify(const struct shirudo_map_view *v,
				      enum shirudo_otel_signal *signal,
				      char *reason, size_t reason_sz);
int shirudo_upatch_maps_otel_build_log(const struct shirudo_map_view *v,
				       char **out, size_t *out_len);
int shirudo_upatch_maps_otel_build_metric(
	const struct shirudo_map_view *v, const struct shirudo_otel_opts *opts,
	char **out, size_t *out_len);
int shirudo_upatch_maps_otel_send(const struct shirudo_map_view *v,
				  enum shirudo_otel_mode mode,
				  const struct shirudo_otel_opts *opts);

#endif /* SHIRUDO_UTIL_UPATCH_MAPS_OTEL_H */
