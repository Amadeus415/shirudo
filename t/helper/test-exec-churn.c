// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "io.h"

extern char **environ;

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
		(uint64_t)ts.tv_nsec;
}

static int parse_positive(const char *text, unsigned long *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || end == text || *end != '\0' || parsed == 0)
		return -1;
	*value = parsed;
	return 0;
}

static int worker(uint64_t deadline, int fd)
{
	char *const argv[] = { (char *)"/bin/true", NULL };
	uint64_t completed = 0;

	for (;;) {
		pid_t child;
		int status;

		if (monotonic_ns() >= deadline)
			break;
		child = fork();
		if (child == 0) {
			execve(argv[0], argv, environ);
			_exit(127);
		}
		if (child < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		while (waitpid(child, &status, 0) < 0) {
			if (errno != EINTR)
				return 1;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			completed++;
	}

	if (shirudo_write_all(fd, &completed, sizeof(completed)))
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	unsigned long duration_sec = 0, workers = 0;
	uint64_t start, deadline, completed = 0;
	int result_fd[2];
	pid_t *children;
	int exit_status = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--duration") && i + 1 < argc) {
			if (parse_positive(argv[++i], &duration_sec))
				return 2;
		} else if (!strcmp(argv[i], "--workers") && i + 1 < argc) {
			if (parse_positive(argv[++i], &workers))
				return 2;
		} else {
			fprintf(stderr, "usage: %s --duration SEC --workers COUNT\n",
				argv[0]);
			return 2;
		}
	}
	if (!duration_sec || !workers || workers > 1024)
		return 2;
	start = monotonic_ns();
	if (!start || duration_sec > UINT64_MAX / UINT64_C(1000000000) ||
		start > UINT64_MAX - duration_sec * UINT64_C(1000000000))
		return 1;
	deadline = start + duration_sec * UINT64_C(1000000000);
	if (pipe(result_fd) != 0)
		return 1;
	children = calloc(workers, sizeof(*children));
	if (!children)
		return 1;

	for (unsigned long i = 0; i < workers; i++) {
		children[i] = fork();
		if (children[i] == 0) {
			close(result_fd[0]);
			_exit(worker(deadline, result_fd[1]) ? 1 : 0);
		}
		if (children[i] < 0) {
			exit_status = 1;
			break;
		}
	}
	close(result_fd[1]);
	for (unsigned long i = 0; i < workers; i++) {
		uint64_t count;

		if (!children[i])
			continue;
		if (waitpid(children[i], NULL, 0) < 0)
			exit_status = 1;
		if (read(result_fd[0], &count, sizeof(count)) == sizeof(count))
			completed += count;
		else
			exit_status = 1;
	}
	close(result_fd[0]);
	free(children);
	if (exit_status)
		return 1;

	uint64_t elapsed = monotonic_ns() - start;
	printf("execs=%" PRIu64 " elapsed_ns=%" PRIu64
	       " execs_per_sec=%.3f workers=%lu\n", completed, elapsed,
	       elapsed ? (double)completed * 1e9 / (double)elapsed : 0.0,
	       workers);
	return 0;
}
