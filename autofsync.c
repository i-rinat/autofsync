// Copyright © 2018  Rinat Ibragimov
//
// This file is part of autofsync.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define _GNU_SOURCE

#include "uthash.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static const size_t g_dirty_limit_initial = 1024 * 1024;
static const size_t g_dirty_limit_low = 1024 * 1024;
static const size_t g_dirty_limit_high = 2ull * 1024 * 1024 * 1024;

static const double g_target_latency_high = 1.1;
static const double g_target_latency_low = 0.9;

#if 0
#define LOG(fmt, ...) printf("autofsync: " fmt "\n", __VA_ARGS__)
#define LOG_(fmt) printf("autofsync: " fmt "\n")
#else
#define LOG(...)
#define LOG_(...)
#endif

#define unlikely(x) __builtin_expect((x), 0)

#define WEAK_SYMBOL __attribute__((weak))

#define ensure_entry_points_initialized()                                      \
    do {                                                                       \
        if (unlikely(!real_entry_points_initialized))                          \
            initialize_real_entry_points();                                    \
    } while (0)

#define get_mode()                                                             \
    ({                                                                         \
        int mode = 0;                                                          \
        if (__OPEN_NEEDS_MODE(oflag)) {                                        \
            va_list a;                                                         \
            va_start(a, oflag);                                                \
            mode = va_arg(a, int);                                             \
            va_end(a);                                                         \
        }                                                                      \
        mode;                                                                  \
    })

struct file {
    int fd;
    size_t dirty;
    size_t dirty_limit;
    dev_t device_id;
    UT_hash_handle hh;
};

static struct file *g_files = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

struct device_dirty_limit {
    dev_t device_id;
    size_t dirty_limit;
    UT_hash_handle hh;
};

static struct device_dirty_limit *g_device_dirty_limit = NULL;

static bool real_entry_points_initialized = false;

static int (*real_open)(const char *fname, int oflag, ...);
static int (*real_open64)(const char *fname, int oflag, ...);
static int (*real_openat)(int atfd, const char *fname, int oflag, ...);
static int (*real_openat64)(int atfd, const char *fname, int oflag, ...);
static int (*real_close)(int);
static ssize_t (*real_write)(int, const void *, ssize_t);
static int (*real_mkstemp)(char *template);
static int (*real_mkostemp)(char *template, int flags);
static int (*real_mkstemps)(char *template, int suffixlen);
static int (*real_mkostemps)(char *template, int suffixlen, int flags);

static void
initialize_real_entry_points(void)
{
    real_open = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_openat64 = dlsym(RTLD_NEXT, "openat64");
    real_write = dlsym(RTLD_NEXT, "write");
    real_close = dlsym(RTLD_NEXT, "close");
    real_mkstemp = dlsym(RTLD_NEXT, "mkstemp");
    real_mkostemp = dlsym(RTLD_NEXT, "mkostemp");
    real_mkstemps = dlsym(RTLD_NEXT, "mkstemps");
    real_mkostemps = dlsym(RTLD_NEXT, "mkostemps");

    real_entry_points_initialized = true;
}

#define HASH_FIND_DEV_T(head, find_dev_t, out)                                 \
    HASH_FIND(hh, head, find_dev_t, sizeof(dev_t), out)

#define HASH_ADD_DEV_T(head, dev_t_field, add)                                 \
    HASH_ADD(hh, head, dev_t_field, sizeof(dev_t), add)

static size_t
get_device_dirty_limit(dev_t device_id)
{
    struct device_dirty_limit *entry = NULL;

    pthread_mutex_lock(&g_lock);
    HASH_FIND_DEV_T(g_device_dirty_limit, &device_id, entry);
    if (entry == NULL) {
        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&g_lock);
            return (size_t)-1;
        }

        entry->device_id = device_id;
        entry->dirty_limit = g_dirty_limit_initial;

        HASH_ADD_DEV_T(g_device_dirty_limit, device_id, entry);
    }

    size_t dirty_limit = entry->dirty_limit;

    pthread_mutex_unlock(&g_lock);
    return dirty_limit;
}

static void
set_device_dirty_limit(dev_t device_id, size_t dirty_limit)
{
    struct device_dirty_limit *entry = NULL;

    pthread_mutex_lock(&g_lock);
    HASH_FIND_DEV_T(g_device_dirty_limit, &device_id, entry);
    if (entry == NULL) {
        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&g_lock);
            return;
        }

        entry->device_id = device_id;
        HASH_ADD_DEV_T(g_device_dirty_limit, device_id, entry);
    }

    entry->dirty_limit = dirty_limit;
    pthread_mutex_unlock(&g_lock);
}

__attribute__((destructor)) static void
destructor_clean_g_device_dirty_limit(void)
{
    struct device_dirty_limit *entry;
    struct device_dirty_limit *tmp;

    pthread_mutex_lock(&g_lock);
    HASH_ITER(hh, g_device_dirty_limit, entry, tmp)
    {
        HASH_DEL(g_device_dirty_limit, entry);
        free(entry);
    }
    pthread_mutex_unlock(&g_lock);
}

static size_t
align_4k(size_t sz)
{
    return sz / 4096 * 4096;
}

static void
account_opened_fd(int fd)
{
    struct stat sb;
    int ret = fstat(fd, &sb);
    if (ret != 0)
        return;

    if (!S_ISREG(sb.st_mode))
        return;

    struct file *new_file = calloc(sizeof(*new_file), 1);
    if (!new_file)
        return;

    new_file->fd = fd;
    new_file->dirty_limit = get_device_dirty_limit(sb.st_dev);
    new_file->dirty = 0;
    new_file->device_id = sb.st_dev;

    struct file *old_file = NULL;
    pthread_mutex_lock(&g_lock);
    HASH_REPLACE_INT(g_files, fd, new_file, old_file);
    pthread_mutex_unlock(&g_lock);

    if (old_file != NULL) {
        LOG_("  unexpected old_file");
        free(old_file);
    }
}

static int
do_open(int (*open_func)(const char *fname, int oflag, ...), const char *fname,
        int oflag, int mode)

{
    int fd = open_func(fname, oflag, mode);
    LOG("  open_func in do_open returns %d", fd);
    if (fd != -1)
        account_opened_fd(fd);

    return fd;
}

static int
do_openat(int (*open_func)(int atfd, const char *fname, int oflag, ...),
          int atfd, const char *fname, int oflag, int mode)

{
    int fd = open_func(atfd, fname, oflag, mode);
    LOG("  open_func in do_openat returns %d", fd);
    if (fd != -1)
        account_opened_fd(fd);

    return fd;
}

WEAK_SYMBOL
int
open(const char *fname, int oflag, ...)
{
    int mode = get_mode();
    LOG("open: fname=%s, oflag=%d, mode=%d", fname, oflag, mode);
    ensure_entry_points_initialized();
    return do_open(real_open, fname, oflag, mode);
}

WEAK_SYMBOL
int
mkstemp(char *template)
{
    LOG("%s: template=%s", __func__, template);
    ensure_entry_points_initialized();
    int fd = real_mkstemp(template);
    if (fd != -1)
        account_opened_fd(fd);
    return fd;
}

WEAK_SYMBOL
int
mkostemp(char *template, int flags)
{
    LOG("%s: template=%s, flags=%d", __func__, template, flags);
    ensure_entry_points_initialized();
    int fd = real_mkostemp(template, flags);
    if (fd != -1)
        account_opened_fd(fd);
    return fd;
}

WEAK_SYMBOL
int
mkstemps(char *template, int suffixlen)
{
    LOG("%s: template=%s, suffixlen=%d", __func__, template, suffixlen);
    ensure_entry_points_initialized();
    int fd = real_mkstemps(template, suffixlen);
    if (fd != -1)
        account_opened_fd(fd);
    return fd;
}

WEAK_SYMBOL
int
mkostemps(char *template, int suffixlen, int flags)
{
    LOG("%s: template=%s, suffixlen=%d, flags=%d", __func__, template,
        suffixlen, flags);
    ensure_entry_points_initialized();
    int fd = real_mkostemps(template, suffixlen, flags);
    if (fd != -1)
        account_opened_fd(fd);
    return fd;
}

WEAK_SYMBOL
int
open64(const char *fname, int oflag, ...)
{
    int mode = get_mode();
    LOG("open64: fname=%s, oflag=%d, mode=%d", fname, oflag, mode);
    ensure_entry_points_initialized();
    return do_open(real_open64, fname, oflag, mode);
}

WEAK_SYMBOL
int
openat(int atfd, const char *fname, int oflag, ...)
{
    int mode = get_mode();
    LOG("openat: atfd=%d, fname=%s, oflag=%d, mode=%d", atfd, fname, oflag,
        mode);
    ensure_entry_points_initialized();
    return do_openat(real_openat, atfd, fname, oflag, mode);
}

WEAK_SYMBOL
int
openat64(int atfd, const char *fname, int oflag, ...)
{
    int mode = get_mode();
    LOG("openat64: atfd=%d, fname=%s, oflag=%d, mode=%d", atfd, fname, oflag,
        mode);
    ensure_entry_points_initialized();
    return do_openat(real_openat64, atfd, fname, oflag, mode);
}

WEAK_SYMBOL
int
close(int fd)
{
    LOG("close: fd = %d", fd);
    ensure_entry_points_initialized();

    struct file *a_file = NULL;
    pthread_mutex_lock(&g_lock);
    HASH_FIND_INT(g_files, &fd, a_file);
    if (a_file) {
        HASH_DEL(g_files, a_file);
        free(a_file);

    } else {
        LOG_("  mismatched close");
    }
    pthread_mutex_unlock(&g_lock);

    return real_close(fd);
}

static void
write_throttle(int fd, ssize_t bytes_written)
{
    struct file *a_file = NULL;
    pthread_mutex_lock(&g_lock);
    HASH_FIND_INT(g_files, &fd, a_file);
    pthread_mutex_unlock(&g_lock);
    if (a_file == NULL) {
        LOG("  non-tracked file %d", fd);
        return;
    }

    a_file->dirty += bytes_written;
    LOG("  dirty = %zu, dirty_limit = %zu", a_file->dirty, a_file->dirty_limit);
    if (a_file->dirty < a_file->dirty_limit)
        return;

    a_file->dirty = 0;
    struct timespec t1;
    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0)
        return;

    if (fdatasync(fd) != 0)
        return;

    struct timespec t2;
    if (clock_gettime(CLOCK_MONOTONIC, &t2) != 0)
        return;

    double elapsed = t2.tv_sec - t1.tv_sec + (t2.tv_nsec - t1.tv_nsec) * 1e-9;
    LOG("  fdatasync took %f seconds", elapsed);

    if (elapsed > g_target_latency_high) {
        double slowdown = elapsed / g_target_latency_high;
        LOG("  slowdown = %f", slowdown);
        if (slowdown > 2) {
            a_file->dirty_limit /= slowdown;

        } else {
            a_file->dirty_limit *= 0.7;
        }

        if (a_file->dirty_limit < g_dirty_limit_low)
            a_file->dirty_limit = g_dirty_limit_low;

        a_file->dirty_limit = align_4k(a_file->dirty_limit);
        LOG("  decreasing dirty_limit to %zu", a_file->dirty_limit);

    } else if (elapsed < g_target_latency_low) {
        a_file->dirty_limit *= 1.3;
        if (a_file->dirty_limit > g_dirty_limit_high)
            a_file->dirty_limit = g_dirty_limit_high;

        a_file->dirty_limit = align_4k(a_file->dirty_limit);
        LOG("  increasing dirty_limit to %zu", a_file->dirty_limit);
    }

    set_device_dirty_limit(a_file->device_id, a_file->dirty_limit);
}

WEAK_SYMBOL
ssize_t
write(int fd, const void *buf, size_t count)
{
    LOG("write: fd = %d, buf = %p, count = %zu", fd, buf, count);
    ensure_entry_points_initialized();

    const ssize_t bytes_written = real_write(fd, buf, count);
    if (bytes_written == -1)
        return -1;

    write_throttle(fd, bytes_written);
    return bytes_written;
}
