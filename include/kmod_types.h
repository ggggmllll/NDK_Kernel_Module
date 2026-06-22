#ifndef KMOD_TYPES_H
#define KMOD_TYPES_H

/*
 * kmod_types.h — 自包含的基本类型与宏（不依赖内核头 / libc）
 *
 * NDK 编译内核模块时没有 <linux/types.h>、也没有 <stdbool.h>，
 * 本头提供模块开发所需的最小类型集合。
 *
 * 注意：MODULE_IMPORT_NS 不在此提供 —— 由 KPatcher 在生成 .ko 时
 * 统一写入 .modinfo 的 import_ns= 项。
 */

/* ---- 基本标量类型 ---- */
typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

typedef u64 phys_addr_t;
typedef u64 dma_addr_t;
typedef unsigned long uintptr_t;

typedef long ssize_t;
typedef unsigned long size_t;
typedef long long loff_t;
typedef unsigned short umode_t;

/* ---- 布尔 / 空指针 ---- */
#ifndef NULL
#define NULL ((void *)0)
#endif
#define true 1
#define false 0
typedef u8 bool;

/* ---- 常用属性 / 节标记（内核里多数是空定义） ---- */
#define __user
#define __init
#define __exit

/* ---- 地址空间边界（AArch64 内核） ---- */
#define KERNEL_SPACE_BASE 0xffffffc000000000UL

/* ---- 通用宏 ---- */
#define offsetof(type, member) ((unsigned long)(&((type *)0)->member))
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* ---- 页 / 对齐 / 位 ---- */
#define PAGE_SIZE  4096
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define BIT(n) (1ULL << (n))

/* ---- GFP / open flag（内核常用） ---- */
#define GFP_KERNEL 0xcc0   /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */
#define O_RDONLY    0
#define O_WRONLY    1

/* =========================================================================
 * 双链表（移植自 linux/list.h 的最小子集）
 * ========================================================================= */
struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev,
                              struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
#define list_for_each_entry(pos, head, member) \
    for (pos = list_first_entry(head, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

#endif /* KMOD_TYPES_H */
