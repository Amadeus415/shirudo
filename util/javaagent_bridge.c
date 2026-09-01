// SPDX-License-Identifier: BSD-2-Clause
/*
 * JNI bridge used by the Shirudo Java-agent examples.  It deliberately uses
 * only the bpf() syscall ABI: the Java agent remains a userspace payload and
 * the companion BPF test-run program is the only kernel object it opens.
 */

#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SHIRUDO_JAVAAGENT_TEST_ROOT \
	"/var/lib/shirudo/bpffs/upatches/"
#define SHIRUDO_JAVAAGENT_NAME_MAX 255

struct javaagent_test_ctx {
	uint64_t jar_id;
	uint64_t hook_id;
};

static pthread_mutex_t javaagent_lock = PTHREAD_MUTEX_INITIALIZER;
static int javaagent_fd = -1;
static char javaagent_name[SHIRUDO_JAVAAGENT_NAME_MAX + 1];

JNIEXPORT jboolean JNICALL
Java_com_security_rasp_ShirudoTelemetry_recordNative(JNIEnv *env, jclass cls,
						jlong jar_id, jlong hook_id,
						jstring telemetry_upatch);

static bool valid_name(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;

	if (!p || !*p || *p == '.')
		return false;
	for (; *p; p++) {
		if (!(('a' <= *p && *p <= 'z') ||
		      ('A' <= *p && *p <= 'Z') ||
		      ('0' <= *p && *p <= '9') || *p == '.' ||
		      *p == '_' || *p == '-'))
			return false;
	}
	return true;
}

static int open_test_program(const char *name)
{
	char path[sizeof(SHIRUDO_JAVAAGENT_TEST_ROOT) +
		  SHIRUDO_JAVAAGENT_NAME_MAX + sizeof("/test")];
	union bpf_attr attr = {};
	int fd;

	if (!valid_name(name) || strlen(name) > SHIRUDO_JAVAAGENT_NAME_MAX)
		return -EINVAL;
	if (javaagent_fd >= 0 && strcmp(javaagent_name, name) == 0)
		return javaagent_fd;
	if (snprintf(path, sizeof(path), "%s%s/test",
		     SHIRUDO_JAVAAGENT_TEST_ROOT, name) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	if (javaagent_fd >= 0) {
		close(javaagent_fd);
		javaagent_fd = -1;
		javaagent_name[0] = '\0';
	}
	memset(&attr, 0, sizeof(attr));
	attr.pathname = (uint64_t)(uintptr_t)path;
	fd = (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (fd < 0)
		return -errno;
	javaagent_fd = fd;
	strncpy(javaagent_name, name, sizeof(javaagent_name) - 1);
	return fd;
}

static bool run_test(int fd, struct javaagent_test_ctx *ctx)
{
	union bpf_attr attr = {};

	attr.test.prog_fd = fd;
	attr.test.ctx_in = (uint64_t)(uintptr_t)ctx;
	attr.test.ctx_size_in = sizeof(*ctx);
	if (syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr)) < 0)
		return false;
	return (int32_t)attr.test.retval >= 0;
}

JNIEXPORT jboolean JNICALL
Java_com_security_rasp_ShirudoTelemetry_recordNative(JNIEnv *env, jclass cls,
						jlong jar_id, jlong hook_id,
						jstring telemetry_upatch)
{
	const char *name;
	struct javaagent_test_ctx ctx;
	int fd;
	bool ok;

	(void)cls;
	if (!env || !telemetry_upatch || jar_id == 0 || hook_id == 0)
		return JNI_FALSE;
	name = (*env)->GetStringUTFChars(env, telemetry_upatch, NULL);
	if (!name)
		return JNI_FALSE;
	ctx.jar_id = (uint64_t)jar_id;
	ctx.hook_id = (uint64_t)hook_id;
	pthread_mutex_lock(&javaagent_lock);
	fd = open_test_program(name);
	ok = fd >= 0 && run_test(fd, &ctx);
	if (!ok && fd >= 0 && (errno == EBADF || errno == ENOENT)) {
		close(javaagent_fd);
		javaagent_fd = -1;
		javaagent_name[0] = '\0';
	}
	pthread_mutex_unlock(&javaagent_lock);
	(*env)->ReleaseStringUTFChars(env, telemetry_upatch, name);
	return ok ? JNI_TRUE : JNI_FALSE;
}
