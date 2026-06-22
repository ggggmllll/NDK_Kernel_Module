#ifndef KMOD_STRING_H
#define KMOD_STRING_H

/*
 * kmod_string.h — 最小 libc：字符串与内存操作
 *
 * 内核态没有 libc，NDK 编译时也不会链接 libc，模块需要的字符串/内存
 * 函数全部自实现。均为 static inline，多个 .c 包含不会冲突。
 *
 * 依赖：kmod_types.h（size_t）。
 */

#ifndef NULL
#define NULL ((void *)0)
#endif

/* ---- 字符串 ---- */
static inline int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *(const unsigned char *)a - *(const unsigned char *)b;
}

static inline int strncmp(const char *a, const char *b, unsigned long n)
{
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? *(const unsigned char *)a - *(const unsigned char *)b : 0;
}

static inline unsigned long strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return p - s;
}

static inline char *strcpy(char *dst, const char *src)
{
    char *d = dst;
    while ((*d++ = *src++));
    return dst;
}

static inline char *strncpy(char *dst, const char *src, unsigned long n)
{
    char *d = dst;
    while (n && (*d++ = *src++)) n--;
    while (n--) *d++ = 0;
    return dst;
}

__attribute__((used))
static inline char *strncat(char *dst, const char *src, unsigned long n)
{
    char *d = dst;
    while (*d) d++;
    while (n-- && (*d++ = *src++));
    if (n == (unsigned long)-1) *d = 0;
    return dst;
}

/* ---- 内存 ---- */
static inline void *memcpy(void *dst, const void *src, unsigned long n)
{
    char *d = dst;
    const char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void *memmove(void *dst, const void *src, unsigned long n)
{
    if (dst < src) return memcpy(dst, src, n);
    char *d = (char *)dst + n;
    const char *s = (const char *)src + n;
    while (n--) *--d = *--s;
    return dst;
}

static inline void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static inline int memcmp(const void *a, const void *b, unsigned long n)
{
    const unsigned char *pa = a, *pb = b;
    while (n-- && *pa == *pb) { pa++; pb++; }
    return n != (unsigned long)-1 ? *pa - *pb : 0;
}

/* ---- 简易格式化辅助（避免 varargs 可移植性问题）---- */
static inline int buf_append(char *buf, int size, int pos, const char *s)
{
    while (pos < size - 1 && *s) buf[pos++] = *s++;
    return pos;
}

static inline int buf_append_dec(char *buf, int size, int pos, int val)
{
    char tmp[12];
    int i = 0;
    if (val < 0) { buf[pos++] = '-'; val = -val; }
    if (val == 0) tmp[i++] = '0';
    else while (val && i < 11) { tmp[i++] = '0' + (val % 10); val /= 10; }
    while (i > 0 && pos < size - 1) buf[pos++] = tmp[--i];
    return pos;
}

#endif /* KMOD_STRING_H */
