/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSNames.h"
#include <string.h>

enum {
	NTFS_NATIVE_HEX_DIGITS_PER_BYTE = 2,
	NTFS_NATIVE_HEX_NIBBLE_BITS = 4,
	NTFS_NATIVE_HEX_DECIMAL_DIGITS = 10,
	NTFS_NATIVE_REFERENCE_DIGITS = sizeof(uint64_t) * NTFS_NATIVE_HEX_DIGITS_PER_BYTE,
	NTFS_NATIVE_ORDINAL_DIGITS = sizeof(uint32_t) * NTFS_NATIVE_HEX_DIGITS_PER_BYTE
};

static const char aliasPrefix[] = "~ntfs-";

struct names_header {
	uint8_t magic[8], version[4], count[4], reference[8];
};

struct names_entry {
	uint8_t ordinal[4], reference[8], units[2], name_namespace, reserved;
};

_Static_assert(sizeof(struct names_header) == 24, "native names header");
_Static_assert(sizeof(struct names_entry) == 16, "native names entry");

static void
store_little(uint8_t *bytes, size_t width, uint64_t value)
{
	size_t i;

	for (i = 0; i < width; i++) {
		bytes[i] = (uint8_t)(value >> (i * CHAR_BIT));
	}
}

BOOL
ntfs_native_entry_visible(const struct ntfs_dirent *entry)
{
	return (entry->reference & NTFS_REFERENCE_RECORD_MASK) >= NTFS_FIRST_USER_RECORD &&
	    entry->name_namespace != NTFS_NAMESPACE_DOS;
}

BOOL
ntfs_native_name_reserved(FSFileName *name)
{
	const uint8_t *bytes = name.data.bytes;

	/* Reserve the complete leading-tilde namespace, including literal NTFS names
	 * resembling an alias. Case variants cannot fall back to the stored literal. */
	return name.data.length != 0 && bytes[0] == '~';
}

static BOOL
valid_stored_name(const struct ntfs_dirent *entry)
{
	size_t i;

	if (entry->name_length == 0 || entry->name_length > NTFS_NAME_MAX) {
		return NO;
	}
	for (i = 0; i < entry->name_length; i++) {
		if (entry->name[i] == 0 || entry->name[i] == '/') {
			return NO;
		}
	}
	return YES;
}

enum ntfs_result
ntfs_native_entry_name(
    const struct ntfs_dirent *entry, uint32_t ordinal, FSFileName **out, BOOL *projected)
{
	char bytes[NTFS_UTF8_NAME_MAX];
	size_t count = 0;
	BOOL reserved;
	enum ntfs_result result;

	*out = nil;
	*projected = NO;
	if (ordinal >= NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT) {
		return NTFS_RANGE;
	}
	if (!valid_stored_name(entry)) {
		return NTFS_CORRUPT;
	}
	reserved = entry->name[0] == '~' ||
	    (entry->name[0] == '.' &&
		(entry->name_length == 1 || (entry->name_length == 2 && entry->name[1] == '.')));
	result = ntfs_utf16_to_utf8(entry->name, entry->name_length, bytes, sizeof(bytes), &count);
	if (!reserved && result == NTFS_OK && count <= NTFS_FSKIT_NATIVE_NAME_BYTES) {
		*out = [FSFileName nameWithBytes:bytes length:count];
		return NTFS_OK;
	}
	*projected = YES;
	*out = [FSFileName
	    nameWithString:[NSString stringWithFormat:@"%s%0*llx-%0*x", aliasPrefix,
			       NTFS_NATIVE_REFERENCE_DIGITS, (unsigned long long)entry->reference,
			       NTFS_NATIVE_ORDINAL_DIGITS, ordinal]];
	return NTFS_OK;
}

static uint8_t
ascii_lower(uint8_t byte)
{
	return byte >= 'A' && byte <= 'Z' ? (uint8_t)(byte - 'A' + 'a') : byte;
}

static BOOL
parse_hex(const uint8_t *bytes, size_t digits, uint64_t *out)
{
	size_t i;
	uint8_t byte, digit;
	uint64_t value = 0;

	for (i = 0; i < digits; i++) {
		byte = ascii_lower(bytes[i]);
		if (byte >= '0' && byte <= '9') {
			digit = byte - '0';
		} else if (byte >= 'a' && byte <= 'f') {
			digit = byte - 'a' + NTFS_NATIVE_HEX_DECIMAL_DIGITS;
		} else {
			return NO;
		}
		value = (value << NTFS_NATIVE_HEX_NIBBLE_BITS) | digit;
	}
	*out = value;
	return YES;
}

BOOL
ntfs_native_alias_parse(FSFileName *name, uint64_t *reference, uint32_t *ordinal)
{
	const uint8_t *bytes = name.data.bytes;
	size_t i, position = sizeof(aliasPrefix) - 1;
	uint64_t index;

	*reference = 0;
	*ordinal = 0;
	if (name.data.length !=
	    position + NTFS_NATIVE_REFERENCE_DIGITS + NTFS_NATIVE_ORDINAL_DIGITS +
		sizeof(uint8_t)) {
		return NO;
	}
	for (i = 0; i < position; i++) {
		if (ascii_lower(bytes[i]) != (uint8_t)aliasPrefix[i]) {
			return NO;
		}
	}
	if (!parse_hex(bytes + position, NTFS_NATIVE_REFERENCE_DIGITS, reference)) {
		return NO;
	}
	position += NTFS_NATIVE_REFERENCE_DIGITS;
	if (bytes[position++] != '-' ||
	    !parse_hex(bytes + position, NTFS_NATIVE_ORDINAL_DIGITS, &index) ||
	    index >= NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT ||
	    *reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
		*reference = 0;
		return NO;
	}
	*ordinal = (uint32_t)index;
	return YES;
}

enum ntfs_result
ntfs_native_entry_at(
    struct ntfs_node *node, uint32_t ordinal, uint32_t maximum, struct ntfs_dirent *out)
{
	struct ntfs_directory *cursor = NULL;
	struct ntfs_dirent entry;
	uint32_t seen = 0, index = 0;
	enum ntfs_result result;

	memset(out, 0, sizeof(*out));
	if (maximum == 0 || maximum > NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT) {
		return NTFS_INVALID;
	}
	if (ordinal >= maximum) {
		return NTFS_RANGE;
	}
	result = ntfs_directory_open(node, &cursor);
	if (result != NTFS_OK) {
		return result;
	}
	while ((result = ntfs_directory_next(cursor, &entry)) == NTFS_OK) {
		if (seen++ == maximum) {
			result = NTFS_RANGE;
			break;
		}
		if (!ntfs_native_entry_visible(&entry)) {
			continue;
		}
		if (index++ == ordinal) {
			*out = entry;
			break;
		}
	}
	ntfs_directory_close(cursor);
	return result;
}

enum ntfs_result
ntfs_native_names_manifest(struct ntfs_node *node, uint64_t reference, uint32_t entryLimit,
    BOOL single, uint32_t ordinal, size_t maximum, NSData **out)
{
	struct ntfs_directory *cursor = NULL;
	struct ntfs_dirent entry;
	struct names_header header = {0};
	struct names_entry wire = {0};
	uint8_t unit[sizeof(uint16_t)];
	uint32_t seen = 0, count = 0;
	size_t i, size;
	NSMutableData *data;
	enum ntfs_result result;

	*out = nil;
	if (entryLimit == 0 || entryLimit > NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT) {
		return NTFS_INVALID;
	}
	if (maximum < sizeof(header)) {
		return NTFS_RANGE;
	}
	if (single) {
		result = ntfs_native_entry_at(node, ordinal, entryLimit, &entry);
	} else {
		result = ntfs_directory_open(node, &cursor);
		if (result == NTFS_OK) {
			result = ntfs_directory_next(cursor, &entry);
		}
	}
	data = [NSMutableData dataWithBytes:&header length:sizeof(header)];
	while (result == NTFS_OK) {
		if (seen++ == entryLimit) {
			result = NTFS_RANGE;
			break;
		}
		if (ntfs_native_entry_visible(&entry)) {
			if (!valid_stored_name(&entry)) {
				result = NTFS_CORRUPT;
				break;
			}
			size = sizeof(wire) + (size_t)entry.name_length * sizeof(uint16_t);
			if (size > maximum - data.length) {
				result = NTFS_RANGE;
				break;
			}
			store_little(wire.ordinal, sizeof(wire.ordinal), single ? ordinal : count);
			store_little(wire.reference, sizeof(wire.reference), entry.reference);
			store_little(wire.units, sizeof(wire.units), entry.name_length);
			wire.name_namespace = entry.name_namespace;
			[data appendBytes:&wire length:sizeof(wire)];
			for (i = 0; i < entry.name_length; i++) {
				store_little(unit, sizeof(unit), entry.name[i]);
				[data appendBytes:unit length:sizeof(unit)];
			}
			count++;
		}
		if (single) {
			break;
		}
		result = ntfs_directory_next(cursor, &entry);
	}
	ntfs_directory_close(cursor);
	if (result != NTFS_OK && result != NTFS_END) {
		return result;
	}
	if (single && count == 0) {
		return NTFS_NOT_FOUND;
	}
	memcpy(header.magic, "NTFSNAM", sizeof(header.magic));
	store_little(header.version, sizeof(header.version), NTFS_NATIVE_NAMES_VERSION);
	store_little(header.count, sizeof(header.count), count);
	store_little(header.reference, sizeof(header.reference), reference);
	memcpy(data.mutableBytes, &header, sizeof(header));
	*out = data;
	return NTFS_OK;
}
