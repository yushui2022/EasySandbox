/* Drop to an unprivileged uid/gid and exec.
 *
 * The QEMU validation initramfs boots as uid 0, but easy-sandbox refuses to
 * launch a payload for uid 0 so that a user-namespace root can never be
 * confused with host root.  The policy suite therefore runs through this
 * helper instead of the busybox applets, whose setpriv build in Ubuntu lacks
 * --reuid/--regid.
 *
 * usage: vm-drop-privs UID GID PROG [ARGS...]
 */
#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: vm-drop-privs UID GID PROG [ARGS...]\n");
        return 2;
    }
    unsigned long uid = strtoul(argv[1], NULL, 10);
    unsigned long gid = strtoul(argv[2], NULL, 10);
    if (setgroups(0, NULL) != 0 || setgid((gid_t)gid) != 0 || setuid((uid_t)uid) != 0) {
        fprintf(stderr, "drop privileges: %s\n", strerror(errno));
        return 1;
    }
    execv(argv[3], &argv[3]);
    fprintf(stderr, "exec %s: %s\n", argv[3], strerror(errno));
    return 1;
}
