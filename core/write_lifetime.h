/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_LIFETIME_H
#define MACHLIN_NTFS_WRITE_LIFETIME_H
#include <ntfs/ntfs.h>

/* Private volatile ownership limits, not NTFS format limits. */
enum {
	NTFS_WRITE_LIFETIME_MAX_OBJECTS = 256,
	NTFS_WRITE_LIFETIME_MAX_LEASES = 4096,
	NTFS_WRITE_LIFETIME_MAX_PENDING = 32
};

struct ntfs_write_lifetime;

struct ntfs_write_lifetime_limits {
	size_t objects, leases, pending;
	uint64_t issued; /* Total one-shot lease and preparation identifiers per epoch. */
};

enum ntfs_write_lifetime_kind { NTFS_WRITE_LIFETIME_OPEN, NTFS_WRITE_LIFETIME_MAPPING };
enum ntfs_write_lifetime_state {
	NTFS_WRITE_LIFETIME_ATTACHED,
	NTFS_WRITE_LIFETIME_DETACHED,
	NTFS_WRITE_LIFETIME_RETIRED
};
enum ntfs_write_lifetime_operation {
	NTFS_WRITE_LIFETIME_UNLINK,
	NTFS_WRITE_LIFETIME_REPLACE,
	NTFS_WRITE_LIFETIME_RETIRE
};
enum ntfs_write_lifetime_outcome {
	NTFS_WRITE_LIFETIME_ABORTED,
	NTFS_WRITE_LIFETIME_COMMITTED,
	NTFS_WRITE_LIFETIME_UNCERTAIN
};

/* Copyable value handles, never mutable owner storage. A duplicate release is
 * STALE. The pointer is compared for identity only, never dereferenced. */
struct ntfs_write_lifetime_token {
	const struct ntfs_write_lifetime *owner;
	uint64_t epoch, serial, reference;
	enum ntfs_write_lifetime_kind kind;
};

struct ntfs_write_lifetime_ticket {
	const struct ntfs_write_lifetime *owner;
	uint64_t epoch, serial, source, victim;
	enum ntfs_write_lifetime_operation operation;
};

struct ntfs_write_lifetime_view {
	enum ntfs_write_lifetime_state state;
	uint32_t names;
	size_t opens, mappings;
	bool pending, eligible, draining, poisoned;
};

/* One allocation retains environment callbacks, all identities and all tables.
 * No read/write callbacks occur. context survives close. Caller serializes every
 * call with its owning mutation/native operation; the helper contains no locks.
 * epoch is nonzero and MUST differ from every former owner whose tokens may
 * survive, including allocator address reuse. Initialization does not recover or
 * infer orphaned FILEs. No object or token transfers across owners.
 *
 * Alias/invalid-pointer errors preserve out. All other errors set *out = NULL.
 * All subsequent failing calls preserve owner state and outputs, except an
 * explicitly completed UNCERTAIN operation, which succeeds and poisons the owner.
 * Returned values prove volatile ownership only, never persistence or authority
 * to clear a bitmap. This private component does not enable open unlink. */
enum ntfs_result ntfs_write_lifetime_create(const struct ntfs_environment *, uint64_t epoch,
    const struct ntfs_write_lifetime_limits *, struct ntfs_write_lifetime **out);

/* Bind an independently validated allocated ordinary FILE and its logical name
 * count (not DOS-alias/physical FILE_NAME count). Each record number occupies one
 * table slot until close, including after retirement. A repeated live binding is
 * EXISTS; another generation is STALE. After committed retirement only the exact
 * next nonzero generation may bind; UINT16_MAX wrap is UNSUPPORTED. Track is not
 * allocation or durable reuse, and names must be nonzero. */
enum ntfs_result ntfs_write_lifetime_track(struct ntfs_write_lifetime *, uint64_t reference,
    uint32_t names);

/* Namespace acquisition requires an attached generation. retain derives a new
 * open/mapping lease from a valid held lease, including after detachment. Pending
 * operations exclude acquisition on both pinned objects. access is admission
 * only: callers retain the token through all I/O and serialize access/release.
 * Drain/poison close access as well as acquisition; release always remains valid. */
enum ntfs_result ntfs_write_lifetime_acquire(struct ntfs_write_lifetime *, uint64_t reference,
    enum ntfs_write_lifetime_kind, struct ntfs_write_lifetime_token *out);
enum ntfs_result ntfs_write_lifetime_retain(struct ntfs_write_lifetime *,
    struct ntfs_write_lifetime_token, enum ntfs_write_lifetime_kind,
    struct ntfs_write_lifetime_token *out);
enum ntfs_result ntfs_write_lifetime_access(
    const struct ntfs_write_lifetime *, struct ntfs_write_lifetime_token);
enum ntfs_result ntfs_write_lifetime_release(
    struct ntfs_write_lifetime *, struct ntfs_write_lifetime_token);
enum ntfs_result ntfs_write_lifetime_inspect(const struct ntfs_write_lifetime *,
    uint64_t reference, struct ntfs_write_lifetime_view *out);

/* UNLINK uses victim and source == 0; REPLACE pins distinct attached source and
 * victim; RETIRE uses victim and source == 0. Unlink/replace removes one logical
 * victim name on commit; replace leaves the source's total name count unchanged.
 * Caller owns exact source/destination edges and atomic namespace mutation.
 * RETIRE requires detached, zero opens/mappings and no pending work.
 *
 * Prepare reserves a one-shot ticket and pins objects before external work. start
 * must precede the FIRST possible transfer; it refuses after drain/poison. A
 * prepared ticket may only finish ABORTED. After start, ABORTED means independently
 * proved unchanged media (not merely an I/O error); COMMITTED requires durable
 * complete publication; UNCERTAIN poisons all access and reuse. Completion remains
 * available during drain/poison so an already-started operation can release pins.
 * No durability assertion is checked here. All starts/completions allocate nothing.
 * Lease releases remain possible while pinned. */
enum ntfs_result ntfs_write_lifetime_prepare(struct ntfs_write_lifetime *,
    enum ntfs_write_lifetime_operation, uint64_t source, uint64_t victim,
    struct ntfs_write_lifetime_ticket *out);
enum ntfs_result ntfs_write_lifetime_start(
    struct ntfs_write_lifetime *, struct ntfs_write_lifetime_ticket);
enum ntfs_result ntfs_write_lifetime_finish(struct ntfs_write_lifetime *,
    struct ntfs_write_lifetime_ticket, enum ntfs_write_lifetime_outcome);

/* Both transitions are terminal and idempotent. They never drop leases, pins or
 * allocation. close requires drain/poison plus zero outstanding leases/tickets;
 * BUSY preserves the owner. Successful close frees only volatile storage, even
 * for attached/detached/uncertain objects. It never reports durable retirement.
 * An in-flight operation must finish before teardown may close its owner. */
void ntfs_write_lifetime_drain(struct ntfs_write_lifetime *);
void ntfs_write_lifetime_poison(struct ntfs_write_lifetime *);
enum ntfs_result ntfs_write_lifetime_close(struct ntfs_write_lifetime *);

#endif
