/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include <ntfs/security.h>
#include "image.h"
#include "path.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

enum {
	INSPECT_READ_BUFFER_BYTES = 1048576,
	HEX_RADIX = 16,
	HEX_DECIMAL_DIGITS = 10,
	DECIMAL_RADIX = 10,
	HEX_NIBBLE_BITS = 4,
	HEX_DIGITS_PER_BYTE = 2,
	HEX_U16_DIGITS = sizeof(uint16_t) * HEX_DIGITS_PER_BYTE,
	HEX_REFERENCE_DIGITS = sizeof(uint64_t) * HEX_DIGITS_PER_BYTE
};

static enum ntfs_result
parse_descriptor_limit(const char *text, uint32_t *value)
{
	uint32_t digit;

	*value = 0;
	if (*text == '\0') {
		return NTFS_INVALID;
	}
	while (*text != '\0') {
		if (*text < '0' || *text > '9') {
			return NTFS_INVALID;
		}
		digit = (uint32_t)(*text++ - '0');
		if (*value > (NTFS_SECURITY_STORE_MAX_DESCRIPTORS - digit) / DECIMAL_RADIX) {
			return NTFS_INVALID;
		}
		*value = *value * DECIMAL_RADIX + digit;
	}
	return *value == 0 ? NTFS_INVALID : NTFS_OK;
}

static void
json_security_store(const struct ntfs_security_store_report *report)
{
	printf("{\"result\":\"%s\",\"stage\":%u,\"complete\":%s,\"descriptor_limit\":%s,"
	       "\"reference\":\"%016" PRIx64 "\",\"security_id\":%" PRIu32 ",\"hash\":%" PRIu32
	       ",\"offset\":\"%" PRIu64 "\",\"cluster\":\"%" PRIu64 "\",\"sii_entries\":\"%" PRIu64
	       "\",\"sdh_entries\":\"%" PRIu64 "\",\"sii_blocks\":\"%" PRIu64
	       "\",\"sdh_blocks\":\"%" PRIu64 "\",\"descriptors\":\"%" PRIu64
	       "\",\"descriptor_bytes\":\"%" PRIu64
	       "\",\"authorization\":false,\"unused_sds_gaps\":\"opaque\"}\n",
	    ntfs_result_string(report->result), report->stage, report->complete ? "true" : "false",
	    report->descriptor_limit ? "true" : "false", report->reference, report->security_id,
	    report->hash, report->offset, report->cluster, report->sii_entries, report->sdh_entries,
	    report->sii_blocks, report->sdh_blocks, report->descriptors, report->descriptor_bytes);
}

static int
hex_digit(char byte)
{
	if (byte >= '0' && byte <= '9') {
		return byte - '0';
	}
	if (byte >= 'a' && byte <= 'f') {
		return byte - 'a' + HEX_DECIMAL_DIGITS;
	}
	if (byte >= 'A' && byte <= 'F') {
		return byte - 'A' + HEX_DECIMAL_DIGITS;
	}
	return -1;
}

static enum ntfs_result
parse_hex(const char *text, uint64_t *value)
{
	size_t length = strlen(text), i;
	int digit;

	*value = 0;
	if (length == 0 || length > HEX_REFERENCE_DIGITS) {
		return NTFS_INVALID;
	}
	for (i = 0; i < length; i++) {
		digit = hex_digit(text[i]);
		if (digit < 0) {
			return NTFS_INVALID;
		}
		*value = *value * HEX_RADIX + (unsigned)digit;
	}
	return NTFS_OK;
}

static enum ntfs_result
parse_name(const char *text, uint16_t *name, size_t *units)
{
	size_t bytes = strlen(text), i;
	int digit;

	*units = 0;
	if (bytes % HEX_U16_DIGITS != 0 || bytes / HEX_U16_DIGITS > NTFS_NAME_MAX) {
		return NTFS_INVALID;
	}
	for (i = 0; i < bytes; i++) {
		digit = hex_digit(text[i]);
		if (digit < 0) {
			return NTFS_INVALID;
		}
		if (i % HEX_U16_DIGITS == 0) {
			name[i / HEX_U16_DIGITS] = 0;
		}
		name[i / HEX_U16_DIGITS] =
		    (uint16_t)((name[i / HEX_U16_DIGITS] << HEX_NIBBLE_BITS) | (unsigned)digit);
	}
	*units = bytes / HEX_U16_DIGITS;
	return NTFS_OK;
}

static void
json_name(const uint16_t *name, size_t length)
{
	size_t i;

	putchar('[');
	for (i = 0; i < length; i++) {
		printf("%s%u", i == 0 ? "" : ",", (unsigned)name[i]);
	}
	putchar(']');
}

static void
json_entry(const struct ntfs_dirent *entry)
{
	printf("{\"reference\":\"%016" PRIx64 "\",\"parent_reference\":\"%016" PRIx64
	       "\",\"size\":\"%" PRIu64 "\",\"file_attributes\":%" PRIu32
	       ",\"namespace\":%u,\"name_utf16\":",
	    entry->reference, entry->parent_reference, entry->size, entry->file_attributes,
	    entry->name_namespace);
	json_name(entry->name, entry->name_length);
	puts("}");
}

static void
json_stat(const struct ntfs_stat *st)
{
	printf("{\"reference\":\"%016" PRIx64 "\",\"size\":\"%" PRIu64
	       "\",\"allocated_size\":\"%" PRIu64 "\",\"links\":%u,\"directory\":%s,"
	       "\"reparse\":%s,\"case_sensitive\":%s,\"file_attributes\":%" PRIu32
	       ",\"security_id\":%" PRIu32 ",\"created\":{\"seconds\":\"%" PRId64
	       "\",\"nanoseconds\":%" PRIu32 "},\"modified\":{\"seconds\":\"%" PRId64
	       "\",\"nanoseconds\":%" PRIu32 "},\"changed\":{\"seconds\":\"%" PRId64
	       "\",\"nanoseconds\":%" PRIu32 "},\"accessed\":{\"seconds\":\"%" PRId64
	       "\",\"nanoseconds\":%" PRIu32 "}}\n",
	    st->reference, st->size, st->allocated_size, st->links,
	    st->directory ? "true" : "false", st->reparse ? "true" : "false",
	    st->case_sensitive ? "true" : "false", st->file_attributes, st->security_id,
	    st->created.seconds, st->created.nanoseconds, st->modified.seconds,
	    st->modified.nanoseconds, st->changed.seconds, st->changed.nanoseconds,
	    st->accessed.seconds, st->accessed.nanoseconds);
}

static enum ntfs_result
copy_stream(struct ntfs_stream *stream)
{
	uint8_t *buffer;
	uint64_t offset = 0;
	size_t done;
	enum ntfs_result result;

	buffer = malloc(INSPECT_READ_BUFFER_BYTES);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	do {
		result = ntfs_stream_read(stream, offset, buffer, INSPECT_READ_BUFFER_BYTES, &done);
		if (result != NTFS_OK) {
			break;
		}
		if (fwrite(buffer, 1, done, stdout) != done) {
			result = NTFS_IO;
			break;
		}
		offset += done;
	} while (done != 0);
	free(buffer);
	return result;
}

/* Numeric references and UTF-16 units avoid locale, normalization and argv's
 * inability to carry unpaired surrogates. All commands remain read-only. */
static enum ntfs_result
inspect_reference(struct ntfs_volume *v, int argc, char **argv)
{
	struct ntfs_node *node = NULL, *child = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_reparse *reparse = NULL;
	struct ntfs_stream_catalog *catalog = NULL;
	struct ntfs_security *security = NULL;
	uint8_t *descriptor = NULL;
	struct ntfs_stream_name stream_name;
	struct ntfs_reparse_info info;
	struct ntfs_dirent entry;
	struct ntfs_stat st;
	uint16_t name[NTFS_NAME_MAX], *target = NULL;
	struct ntfs_link_counts links;
	uint64_t reference;
	size_t length = 0, capacity = 0;
	uint32_t stream_index;
	enum ntfs_result result;

	if (argc < 4 || argc > 5) {
		return NTFS_INVALID;
	}
	result = parse_hex(argv[3], &reference);
	if (result == NTFS_OK && strcmp(argv[2], "security-id") == 0) {
		if (reference > UINT32_MAX) {
			result = NTFS_INVALID;
		}
	} else if (result == NTFS_OK) {
		result = ntfs_node_open(v, reference, &node);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (strcmp(argv[2], "stat-ref") == 0 && argc == 4) {
		result = ntfs_node_stat(node, &st);
		if (result == NTFS_OK) {
			json_stat(&st);
		}
	} else if (strcmp(argv[2], "links-ref") == 0 && argc == 4) {
		result = ntfs_node_link_counts(node, &links);
		if (result == NTFS_OK) {
			printf("{\"physical_names\":%u,\"primary_names\":%u,\"dos_aliases\":%u}\n",
			    links.physical_names, links.primary_names, links.dos_aliases);
		}
	} else if (strcmp(argv[2], "ls-ref") == 0 && argc == 4) {
		result = ntfs_directory_open(node, &directory);
		if (result != NTFS_OK) {
			goto finish;
		}
		while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
			json_entry(&entry);
		}
		if (result == NTFS_END) {
			result = NTFS_OK;
		}
	} else if (strcmp(argv[2], "streams-ref") == 0 && argc == 4) {
		result = ntfs_stream_catalog_open(node, NTFS_MAX_STREAM_CATALOG_ENTRIES, &catalog);
		if (result != NTFS_OK) {
			goto finish;
		}
		for (stream_index = 0; stream_index < ntfs_stream_catalog_count(catalog);
		    stream_index++) {
			result = ntfs_stream_catalog_entry(catalog, stream_index, &stream_name);
			if (result != NTFS_OK) {
				goto finish;
			}
			printf("{\"name_utf16\":");
			json_name(stream_name.units, stream_name.length);
			puts("}");
		}
	} else if ((strcmp(argv[2], "security-ref") == 0 || strcmp(argv[2], "security-id") == 0) &&
	    argc == 4) {
		result = node != NULL ? ntfs_security_open(node, &security)
				      : ntfs_security_resolve(v, (uint32_t)reference, &security);
		if (result != NTFS_OK) {
			goto finish;
		}
		capacity = ntfs_security_size(security);
		descriptor = malloc(capacity);
		if (descriptor == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
		result = ntfs_security_copy(security, descriptor, capacity, &length);
		if (result == NTFS_OK && fwrite(descriptor, 1, length, stdout) != length) {
			result = NTFS_IO;
		}
	} else if (strcmp(argv[2], "lookup-ref") == 0 && argc == 5) {
		result = parse_name(argv[4], name, &length);
		if (result == NTFS_OK) {
			result = ntfs_lookup_entry(node, name, length, &child, &entry);
		}
		if (result == NTFS_OK) {
			json_entry(&entry);
		}
	} else if (strcmp(argv[2], "cat-ref") == 0) {
		if (argc == 5) {
			result = parse_name(argv[4], name, &length);
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_open(node, name, length, &stream);
		}
		if (result == NTFS_OK) {
			result = copy_stream(stream);
		}
	} else if (strcmp(argv[2], "reparse-ref") == 0 && argc == 4) {
		result = ntfs_reparse_open(node, &reparse);
		if (result != NTFS_OK) {
			goto finish;
		}
		ntfs_reparse_get_info(reparse, &info);
		capacity = info.substitute_length > info.print_length ? info.substitute_length
								      : info.print_length;
		if (capacity != 0) {
			target = malloc(capacity * sizeof(*target));
			if (target == NULL) {
				result = NTFS_NO_MEMORY;
				goto finish;
			}
		}
		printf("{\"tag\":%" PRIu32 ",\"kind\":%u,\"flags\":%" PRIu32, info.tag, info.kind,
		    info.flags);
		if (info.kind == NTFS_REPARSE_SYMLINK || info.kind == NTFS_REPARSE_MOUNT_POINT) {
			result = ntfs_reparse_name(
			    reparse, NTFS_REPARSE_SUBSTITUTE_NAME, target, capacity, &length);
			if (result == NTFS_OK) {
				printf(",\"substitute_utf16\":");
				json_name(target, length);
				result = ntfs_reparse_name(
				    reparse, NTFS_REPARSE_PRINT_NAME, target, capacity, &length);
			}
			if (result == NTFS_OK) {
				printf(",\"print_utf16\":");
				json_name(target, length);
			}
		}
		puts("}");
	} else {
		result = NTFS_INVALID;
	}
finish:
	free(target);
	free(descriptor);
	ntfs_security_close(security);
	ntfs_stream_catalog_close(catalog);
	ntfs_reparse_close(reparse);
	ntfs_directory_close(directory);
	ntfs_stream_close(stream);
	ntfs_node_close(child);
	ntfs_node_close(node);
	return result;
}

static enum ntfs_result
print_reparse(struct ntfs_reparse *reparse)
{
	const char *kind;
	struct ntfs_reparse_info info;
	uint16_t *name;
	size_t capacity, length, i;
	enum ntfs_reparse_name_type which;
	enum ntfs_result result = NTFS_OK;

	ntfs_reparse_get_info(reparse, &info);
	switch (info.kind) {
	case NTFS_REPARSE_SYMLINK:
		kind = "symlink";
		break;
	case NTFS_REPARSE_MOUNT_POINT:
		kind = "mount-point";
		break;
	case NTFS_REPARSE_WOF:
		kind = "wof";
		break;
	case NTFS_REPARSE_CLOUD:
		kind = "cloud";
		break;
	default:
		kind = "unknown";
		break;
	}
	printf("tag=0x%08" PRIx32 "\nkind=%s\nflags=0x%08" PRIx32 "\n", info.tag, kind, info.flags);
	if (info.kind != NTFS_REPARSE_SYMLINK && info.kind != NTFS_REPARSE_MOUNT_POINT) {
		return NTFS_OK;
	}
	capacity =
	    info.substitute_length > info.print_length ? info.substitute_length : info.print_length;
	name = malloc(capacity * sizeof(*name));
	if (name == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (which = NTFS_REPARSE_SUBSTITUTE_NAME; which <= NTFS_REPARSE_PRINT_NAME; which++) {
		result = ntfs_reparse_name(reparse, which, name, capacity, &length);
		if (result != NTFS_OK) {
			break;
		}
		printf("%s_utf16=", which == NTFS_REPARSE_SUBSTITUTE_NAME ? "substitute" : "print");
		for (i = 0; i < length; i++) {
			printf("%s%04x", i == 0 ? "" : " ", (unsigned)name[i]);
		}
		putchar('\n');
	}
	free(name);
	return result;
}

int
main(int argc, char **argv)
{
	struct ntfs_image image;
	struct ntfs_volume *v = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_reparse *reparse = NULL;
	struct ntfs_info info;
	struct ntfs_security_store_limits store_limits;
	struct ntfs_security_store_report store_report;
	struct ntfs_stat st;
	struct ntfs_dirent entry;
	uint16_t stream_name[NTFS_NAME_MAX];
	char name[NTFS_UTF8_NAME_MAX + 1];
	size_t done, length = 0;
	uint64_t free_clusters;
	enum ntfs_result result;
	int error;
	bool store_reported = false;

	if (argc < 3) {
		fprintf(stderr,
		    "usage: ntfs-inspect IMAGE info|ls|stat|cat|reparse [PATH] [STREAM]\n"
		    "       ntfs-inspect IMAGE info-json\n"
		    "       ntfs-inspect IMAGE security-id HEX_SECURITY_ID\n"
		    "       ntfs-inspect IMAGE security-store [MAX_DESCRIPTORS]\n"
		    "       ntfs-inspect IMAGE "
		    "stat-ref|links-ref|ls-ref|reparse-ref|streams-ref|security-ref "
		    "HEX_REFERENCE\n"
		    "       ntfs-inspect IMAGE cat-ref|lookup-ref HEX_REFERENCE [UTF16_HEX]\n");
		return 2;
	}
	error = ntfs_image_open(argv[1], &image);
	if (error != 0) {
		fprintf(stderr, "image: %s\n", strerror(error));
		return 1;
	}
	result = ntfs_mount(&image.environment, NULL, &v);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (strcmp(argv[2], "security-store") == 0) {
		ntfs_security_store_default_limits(&store_limits);
		if (argc > 4) {
			result = NTFS_INVALID;
		} else if (argc == 4) {
			result = parse_descriptor_limit(argv[3], &store_limits.max_descriptors);
		}
		if (result == NTFS_OK) {
			result = ntfs_security_store_validate(v, &store_limits, &store_report);
			json_security_store(&store_report);
			store_reported = true;
		}
		goto finish;
	}
	if (strcmp(argv[2], "info-json") == 0 && argc == 3) {
		ntfs_get_info(v, &info);
		result = ntfs_root(v, &node);
		if (result == NTFS_OK) {
			result = ntfs_node_stat(node, &st);
		}
		if (result == NTFS_OK) {
			printf("{\"serial\":\"%016" PRIx64 "\",\"size_bytes\":\"%" PRIu64
			       "\",\"cluster_count\":\"%" PRIu64
			       "\",\"sector_size\":%u,\"cluster_size\":%u,\"record_size\":%u,"
			       "\"index_size\":%u,\"volume_flags\":%u,\"major_version\":%u,"
			       "\"minor_version\":%u,\"root_reference\":\"%016" PRIx64 "\"}\n",
			    info.serial, info.size_bytes, info.cluster_count, info.sector_size,
			    info.cluster_size, info.record_size, info.index_size, info.volume_flags,
			    info.major_version, info.minor_version, st.reference);
		}
		goto finish;
	}
	if (strstr(argv[2], "-ref") != NULL || strcmp(argv[2], "security-id") == 0) {
		result = inspect_reference(v, argc, argv);
		goto finish;
	}
	if (strcmp(argv[2], "info") == 0) {
		ntfs_get_info(v, &info);
		result = ntfs_count_free_clusters(v, &free_clusters);
		if (result == NTFS_OK) {
			printf("NTFS "
			       "%u.%u\nlabel=%s\nsector=%u\ncluster=%u\nrecord=%u\nindex=%u\nbytes="
			       "%" PRIu64 "\nfree_clusters=%" PRIu64 "\n",
			    info.major_version, info.minor_version, info.label, info.sector_size,
			    info.cluster_size, info.record_size, info.index_size, info.size_bytes,
			    free_clusters);
		}
		goto finish;
	}
	result = ntfs_tool_resolve(v, argc > 3 ? argv[3] : "/", &node);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (strcmp(argv[2], "stat") == 0) {
		result = ntfs_node_stat(node, &st);
		if (result == NTFS_OK) {
			printf("reference=%" PRIu64 "\nsize=%" PRIu64 "\nallocated=%" PRIu64
			       "\nlinks=%u\ndirectory=%d\n",
			    st.reference, st.size, st.allocated_size, st.links, st.directory);
		}
	} else if (strcmp(argv[2], "reparse") == 0) {
		result = ntfs_reparse_open(node, &reparse);
		if (result == NTFS_OK) {
			result = print_reparse(reparse);
		}
	} else if (strcmp(argv[2], "ls") == 0) {
		result = ntfs_directory_open(node, &directory);
		if (result != NTFS_OK) {
			goto finish;
		}
		while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
			if (entry.name_namespace == NTFS_NAMESPACE_DOS) {
				continue;
			}
			result = ntfs_utf16_to_utf8(
			    entry.name, entry.name_length, name, NTFS_UTF8_NAME_MAX, &done);
			if (result != NTFS_OK) {
				break;
			}
			name[done] = 0;
			printf("%s\n", name);
		}
		if (result == NTFS_END) {
			result = NTFS_OK;
		}
	} else if (strcmp(argv[2], "cat") == 0) {
		if (argc > 4) {
			result = ntfs_utf8_to_utf16(
			    argv[4], strlen(argv[4]), stream_name, NTFS_NAME_MAX, &length);
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_open(node, stream_name, length, &stream);
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		result = copy_stream(stream);
	} else {
		result = NTFS_INVALID;
	}
finish:
	ntfs_directory_close(directory);
	ntfs_stream_close(stream);
	ntfs_reparse_close(reparse);
	ntfs_node_close(node);
	if (ntfs_unmount(v) != NTFS_OK) {
		result = NTFS_BUSY;
	}
	ntfs_image_close(&image);
	if (result != NTFS_OK) {
		if (!store_reported) {
			fprintf(stderr, "%s\n", ntfs_result_string(result));
		}
		return 1;
	}
	return 0;
}
