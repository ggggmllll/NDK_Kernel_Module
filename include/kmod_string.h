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

/* ---- 字符串查找 / 拼接 / 长度 ---- */
static inline char *strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return c == 0 ? (char *)s : NULL;
}

static inline char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    while (*s) {
        if (*s == (char)c) last = s;
        s++;
    }
    return c == 0 ? (char *)s : (char *)last;
}

static inline char *strstr(const char *haystack, const char *needle)
{
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return (char *)haystack;
    }
    return NULL;
}

static inline char *strcat(char *dst, const char *src)
{
    char *d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

static inline unsigned long strnlen(const char *s, unsigned long maxlen)
{
    unsigned long len = 0;
    while (len < maxlen && s[len]) len++;
    return len;
}

/* ---- 内存查找 ---- */
static inline void *memchr(const void *s, int c, unsigned long n)
{
    const unsigned char *p = s;
    while (n--) {
        if (*p == (unsigned char)c) return (void *)p;
        p++;
    }
    return NULL;
}

static inline void *memrchr(const void *s, int c, unsigned long n)
{
    const unsigned char *p = (const unsigned char *)s + n;
    while (n--) {
        p--;
        if (*p == (unsigned char)c) return (void *)p;
    }
    return NULL;
}

/* ---- 数字解析 ---- */
static inline long strtol(const char *s, char **end, int base)
{
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;

    if ((base == 0 || base == 16) && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2; base = 16;
    } else if (base == 0) {
        base = (*p == '0') ? 8 : 10;
    }

    unsigned long val = 0;
    while (*p) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'z') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'Z') d = *p - 'A' + 10;
        else break;
        if (d >= base) break;
        val = val * base + d;
        p++;
    }
    if (end) *end = (char *)p;
    return neg ? -(long)val : (long)val;
}

static inline unsigned long strtoul(const char *s, char **end, int base)
{
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '+') p++;
    if ((base == 0 || base == 16) && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2; base = 16;
    } else if (base == 0) {
        base = (*p == '0') ? 8 : 10;
    }
    unsigned long val = 0;
    while (*p) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'z') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'Z') d = *p - 'A' + 10;
        else break;
        if (d >= base) break;
        val = val * base + d;
        p++;
    }
    if (end) *end = (char *)p;
    return val;
}

/* ---- 简易 snprintf（%s/%d/%u/%x/%c/%p/%%，不支持宽度精度）----
 * 用 __builtin_va_list 绕过对 <stdarg.h> 的依赖。
 * local_syms 导出后 KPM 可通过符号解析调用。 */
__attribute__((used))
static inline int snprintf(char *buf, unsigned long size, const char *fmt, ...)
{
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    unsigned long pos = 0;

    while (*fmt && pos + 1 < size) {
        if (*fmt != '%') { buf[pos++] = *fmt++; continue; }
        fmt++;
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos + 1 < size) buf[pos++] = *s++;
            break;
        }
        case 'd': {
            int v = __builtin_va_arg(ap, int);
            if (v < 0) { if (pos + 1 < size) buf[pos++] = '-'; v = -v; }
            char tmp[12]; int i = 0;
            if (v == 0) tmp[i++] = '0';
            while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
            while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            break;
        }
        case 'u': {
            unsigned int v = __builtin_va_arg(ap, unsigned int);
            char tmp[12]; int i = 0;
            if (v == 0) tmp[i++] = '0';
            while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
            while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            break;
        }
        case 'x': {
            unsigned int v = __builtin_va_arg(ap, unsigned int);
            char tmp[12]; int i = 0;
            if (v == 0) tmp[i++] = '0';
            while (v) { int d = v & 0xF; tmp[i++] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; }
            while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            break;
        }
        case 'c': {
            buf[pos++] = (char)__builtin_va_arg(ap, int);
            break;
        }
        case 'p': {
            unsigned long v = (unsigned long)__builtin_va_arg(ap, void *);
            if (pos + 1 < size) buf[pos++] = '0';
            if (pos + 1 < size) buf[pos++] = 'x';
            char tmp[16]; int i = 0;
            if (v == 0) tmp[i++] = '0';
            while (v) { int d = v & 0xF; tmp[i++] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; }
            while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            break;
        }
        case '%': buf[pos++] = '%'; break;
        case 'l': {  /* %lu / %ld / %lx */
            fmt++;
            if (*fmt == 'u') {
                unsigned long v = __builtin_va_arg(ap, unsigned long);
                char tmp[24]; int i = 0;
                if (v == 0) tmp[i++] = '0';
                while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
                while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            } else if (*fmt == 'd') {
                long v = __builtin_va_arg(ap, long);
                if (v < 0) { if (pos + 1 < size) buf[pos++] = '-'; v = -v; }
                char tmp[24]; int i = 0;
                if (v == 0) tmp[i++] = '0';
                while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
                while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            } else if (*fmt == 'x') {
                unsigned long v = __builtin_va_arg(ap, unsigned long);
                char tmp[20]; int i = 0;
                if (v == 0) tmp[i++] = '0';
                while (v) { int d = v & 0xF; tmp[i++] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; }
                while (i > 0 && pos + 1 < size) buf[pos++] = tmp[--i];
            }
            break;
        }
        default: buf[pos++] = '%'; buf[pos++] = *fmt; break;
        }
        fmt++;
    }
    buf[pos < size ? pos : size - 1] = 0;
    __builtin_va_end(ap);
    return (int)pos;
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
