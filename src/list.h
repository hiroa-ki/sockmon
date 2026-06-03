#ifndef _LIST_H
#define _LIST_H

#define __same_type(a, b)	\
	__builtin_types_compatible_p(typeof(a), typeof(b))

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name)	{ &(name), &(name) }

#define LIST_HEAD(name)	\
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
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

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline void list_del(struct list_head *entry)
{
	__list_del_entry(entry);
}

static inline int list_is_head(const struct list_head *list,
			       const struct list_head *head)
{
	return list == head;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define list_entry(ptr, type, member)	\
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member)	\
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member)	\
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_entry_is_head(pos, head, member)	\
	list_is_head(&pos->member, (head))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member);			\
	     pos = n, n = list_next_entry(n, member))

#endif	/* _LIST_H */
