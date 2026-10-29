// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>

static volatile __u32 *marker;

__attribute__((noinline, used)) void _zend_bailout(void)
{
	*marker = 1;
	_exit(42);
}

int main(int argc, char **argv)
{
	int guarded, status;
	pid_t child;
	int ret;

	if (argc != 2)
		return 2;
	if (strcmp(argv[1], "plain") && strcmp(argv[1], "guarded"))
		return 2;
	guarded = !strcmp(argv[1], "guarded");
	marker = mmap(NULL, sizeof(*marker), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (marker == MAP_FAILED)
		return 2;
	*marker = 0;
	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		*marker = 0;
		_zend_bailout();
	}
	if (waitpid(child, &status, 0) != child)
		return 2;
	printf("signal=%d exit=%d marker=%u\n",
	       WIFSIGNALED(status) ? WTERMSIG(status) : 0,
	       WIFEXITED(status) ? WEXITSTATUS(status) : -1, *marker);
	if (guarded)
		ret = !(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
			!*marker);
	else
		ret = !(WIFEXITED(status) && WEXITSTATUS(status) == 42 &&
			*marker == 1);
	munmap((void *)marker, sizeof(*marker));
	return ret;
}
