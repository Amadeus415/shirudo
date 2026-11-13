// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXEC_DENIED 77
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

__attribute__((noinline, used)) void php_request_startup(void)
{
	asm volatile("" ::: "memory");
}

__attribute__((noinline, used)) void php_request_shutdown(void)
{
	asm volatile("" ::: "memory");
}

static void attempt_exec(int by_fd)
{
	char program[] = "/usr/bin/true";
	char * const args[] = { program, NULL };
	char * const env[] = { NULL };
	int fd;

	if (by_fd) {
		fd = open(args[0], O_PATH | O_CLOEXEC);
		if (fd < 0)
			_exit(2);
		execveat(fd, "", args, env, AT_EMPTY_PATH);
	} else {
		execve(args[0], args, env);
	}
	_exit(errno == EPERM ? EXEC_DENIED : 2);
}

static int child_status(pid_t child)
{
	int status;

	if (child < 0 || waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static void *thread_exec(void *unused)
{
	(void)unused;
	attempt_exec(0);
	return NULL;
}

static void run_case(const char *name)
{
	pthread_t thread;
	pid_t child;
	int depth;

	if (!strcmp(name, "unmarked")) {
		if (prctl(PR_SET_NAME, "apache2", 0, 0, 0))
			_exit(2);
		attempt_exec(0);
	}
	php_request_startup();
	if (!strcmp(name, "renamed")) {
		if (prctl(PR_SET_NAME, "unrelated", 0, 0, 0))
			_exit(2);
	} else if (!strcmp(name, "descendant")) {
		for (depth = 0; depth < 2; depth++) {
			child = fork();
			if (child)
				_exit(child_status(child));
		}
	} else if (!strcmp(name, "thread")) {
		if (pthread_create(&thread, NULL, thread_exec, NULL))
			_exit(2);
		pthread_join(thread, NULL);
		_exit(2);
	} else if (!strcmp(name, "shutdown")) {
		php_request_shutdown();
	}
	attempt_exec(!strcmp(name, "execveat"));
}

int main(int argc, char **argv)
{
	static const char * const cases[] = {
		"unmarked", "direct", "renamed", "descendant", "thread",
		"execveat", "shutdown",
	};
	int guarded, expected, status;
	pid_t child;
	size_t i;

	if (argc != 2 || (strcmp(argv[1], "baseline") &&
			  strcmp(argv[1], "guarded")))
		return 2;
	guarded = !strcmp(argv[1], "guarded");
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fflush(stdout);
		child = fork();
		if (!child)
			run_case(cases[i]);
		status = child_status(child);
		expected = guarded && i ? EXEC_DENIED : 0;
		printf("%s %s status=%d expected=%d\n",
		       argv[1], cases[i], status, expected);
		if (status != expected)
			return 1;
	}
	return 0;
}
