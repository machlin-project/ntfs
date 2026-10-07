/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_PAYLOAD_H
#define MACHLIN_NTFS_WRITE_PAYLOAD_H
#include <ntfs/logfile_encode.h>

/* Owned writer scratch only: descriptor, borrowed payloads, output and byte
 * count are disjoint. Preserve native empty-span offsets, reserved no-LCN
 * capacity and compensation's declared omitted-undo length. This helper shares
 * packet framing without exposing another component's retained owner. */
enum ntfs_result ntfs_write_payload_encode(
    const struct ntfs_logfile_update_input *, void *, size_t capacity, uint32_t *bytes);

#endif
