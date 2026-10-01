/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <FSKit/FSKit.h>
#include <ntfs/ntfs.h>
#include <limits.h>

enum {
	NTFS_FSKIT_NATIVE_NAME_BYTES = NAME_MAX,
	/* Bounds a complete scan, including DOS aliases and hidden metadata. */
	NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT = 1048576,
	NTFS_NATIVE_NAMES_VERSION = 1
};

BOOL ntfs_native_entry_visible(const struct ntfs_dirent *);
BOOL ntfs_native_name_reserved(FSFileName *);
/* Ordinary UTF-8 components pass through; reserved, unpaired or oversized names
 * use a link's visible ordinal and full file reference in its owning directory.
 * The original UTF-16 never passes through NSString. */
enum ntfs_result ntfs_native_entry_name(
    const struct ntfs_dirent *, uint32_t, FSFileName **, BOOL *);
BOOL ntfs_native_alias_parse(FSFileName *, uint64_t *, uint32_t *);
/* Independent cursors never change an item's enumeration continuation. */
enum ntfs_result ntfs_native_entry_at(struct ntfs_node *, uint32_t, uint32_t, struct ntfs_dirent *);
/* The directory manifest may exceed the response budget. A single-entry query
 * remains bounded independently of directory size. Output is nil on failure. */
enum ntfs_result ntfs_native_names_manifest(
    struct ntfs_node *, uint64_t, uint32_t, BOOL, uint32_t, size_t, NSData **);
