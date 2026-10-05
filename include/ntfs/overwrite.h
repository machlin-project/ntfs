/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_OVERWRITE_H
#define MACHLIN_NTFS_OVERWRITE_H
#include <ntfs/recovery.h>
#include <ntfs/validate.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NTFS_OVERWRITE_API_VERSION = 1,
	NTFS_OVERWRITE_MAX_BYTES = 1024 * 1024,
	NTFS_OVERWRITE_MAX_PATH_UNITS = 4096,
	NTFS_OVERWRITE_MIN_ALIGNMENT = 512,
	NTFS_OVERWRITE_MAX_ALIGNMENT = 65536
};

struct ntfs_overwrite_environment {
	struct ntfs_environment reader;
	uint32_t api_version, alignment;
	/* Claim excludes every other reader/mutator for the complete owner lifetime.
	 * The backend authorizes access to this resource before claim succeeds.
	 * Failed claim acquires nothing; unclaim performs no I/O. */
	enum ntfs_result (*claim)(void *);
	void (*unclaim)(void *);
	/* Exact successful transfers. Errors may change any requested bytes and
	 * report a bounded transferred prefix; they permanently poison this owner. */
	enum ntfs_result (*write)(void *, uint64_t, const void *, size_t, size_t *);
	/* Must persist through every volatile cache. A cache-only flush is invalid. */
	enum ntfs_result (*persist)(void *);
};

struct ntfs_overwrite_admission {
	struct ntfs_validation_report validation;
	struct ntfs_recovery_report recovery;
	struct ntfs_info info;
	bool claimed, quiescent, persistence_succeeded;
};

struct ntfs_overwrite_report {
	uint64_t requested_bytes, completed_bytes, physical_bytes;
	uint32_t writes;
	bool persisted, poisoned;
};

struct ntfs_overwrite;

/* Experimental metadata-preserving data overwrite, separate from filesystem
 * write(2). Only already initialized, ordinary nonresident unnamed file ranges
 * qualify. No timestamps, attributes, sizes, allocation, namespace, USN or native
 * journal bytes change. It is not wired into FSKit mutation operations.
 * Admission requires exclusive authorized resource ownership, full allocation
 * validation, absence of hiberfil.sys and a complete native quiet checkpoint:
 * one targetless Noop followed by its empty owning restart, no unfinished tail.
 * Other native histories remain unsupported; no replay is simulated.
 * The existing read environment stays unchanged. Temporary immutable read owners
 * and every child close before the first physical write. Caller serializes all
 * calls and retains environment/context until close. Close releases ownership
 * without I/O, including poisoned owners. Failed open publishes NULL.
 * Core allocation is bounded by the named live-memory policy. */
enum ntfs_result ntfs_overwrite_open(const struct ntfs_overwrite_environment *,
    struct ntfs_overwrite_admission *, struct ntfs_overwrite **);
void ntfs_overwrite_close(struct ntfs_overwrite *);

/* Bounded absolute UTF-16 lookup, without reparse traversal. Output is zero on
 * error. No returned read owner or node survives this operation. */
enum ntfs_result ntfs_overwrite_resolve(
    struct ntfs_overwrite *, const uint16_t *, size_t, uint64_t *reference);

/* The complete private aligned image and mapping plan precede mutation. Range,
 * format, allocation, read and quota failures leave the device unchanged and
 * allow retry. Exact write plus real persistence precede success. Any attempted
 * write/barrier failure poisons this owner; further operations return IO.
 * completed_bytes is the prefix covered by exact successful writes, not a claim
 * of durability after failure. Failed physical calls remain uncertain, including
 * callbacks reporting zero transferred bytes. No whole-range atomicity is promised.
 * Borrowed input/report/owner must be disjoint and immutable during this call.
 * Native filesystem authorization and metadata mutation remain separate. */
enum ntfs_result ntfs_overwrite_range(struct ntfs_overwrite *, uint64_t reference, uint64_t offset,
    const void *, size_t, struct ntfs_overwrite_report *);

#ifdef __cplusplus
}
#endif
#endif
