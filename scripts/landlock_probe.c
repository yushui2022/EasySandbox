#define _GNU_SOURCE
#include <errno.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__)
#define __NR_landlock_create_ruleset 444
#elif defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#endif
#endif

static int landlock_create_ruleset(const void *attr, size_t size, __u32 flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

int main(void) {
    errno = 0;
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    int saved = errno;
    printf("{\"abi\":%d,\"errno\":%d,\"no_new_privs\":", abi, saved);
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1) {
        fputs("true", stdout);
    } else {
        fputs("false", stdout);
    }
    printf(",\"abi_at_least_3\":%s}\n", abi >= 3 ? "true" : "false");
    return abi >= 3 ? 0 : 2;
}
