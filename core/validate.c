/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/validate.h>

enum {
	VALIDATION_DEFAULT_RECORDS = 1048576,
	VALIDATION_DEFAULT_RUNS = 1048576,
	VALIDATION_DEFAULT_LINKS = 1048576,
	VALIDATION_DEFAULT_MEMORY = 64 * 1024 * 1024,
	VALIDATION_DEFAULT_READ_CALLS = 1048576,
	VALIDATION_VECTOR_START = 16,
	VALIDATION_VECTOR_GROWTH = 2,
	VALIDATION_FILENAME_SOURCE = 1,
	VALIDATION_INDEX_SOURCE = 2,
	VALIDATION_LINK_PAIR = 2,
	VALIDATION_RESERVED_FIRST = 12,
	VALIDATION_RESERVED_LAST = 15,
	VALIDATION_DIRECTORY_VISITING = 1,
	VALIDATION_DIRECTORY_VISITED = 2
};

#define VALIDATION_DEFAULT_READ_BYTES (UINT64_C(4) * 1024 * 1024 * 1024)
#define VALIDATION_DEFAULT_WORK (UINT64_C(4) * 1024 * 1024 * 1024)

struct validation_record {
	uint64_t reference, base, parent;
	uint32_t primary_names;
	uint16_t flags, links;
	uint8_t directory_state;
	bool dos_names;
	bool reserved_empty;
	bool reserved_inert;
};

struct validation_run {
	uint64_t first, end, reference;
	uint32_t type;
};

struct validation_link {
	uint64_t parent, reference;
	uint32_t offset;
	uint16_t length;
	uint8_t name_namespace, source;
};

struct validation {
	struct ntfs_environment source;
	struct ntfs_validation_limits limits;
	struct ntfs_validation_report *report;
	struct ntfs_volume *volume;
	struct validation_record *records;
	struct validation_run *runs;
	struct validation_link *links;
	uint16_t *names;
	uint32_t run_count, run_capacity, link_count, link_capacity;
	uint32_t name_count, name_capacity;
	size_t memory;
	uint64_t deferred_dos_reference;
	enum ntfs_result failure;
};

static enum ntfs_result remember_link(
    struct validation *, uint64_t, uint64_t, const uint16_t *, uint16_t, uint8_t, uint8_t);
static enum ntfs_result scan_attributes(struct validation *);

void
ntfs_validation_default_limits(struct ntfs_validation_limits *limits)
{
	if (limits != NULL) {
		*limits = (struct ntfs_validation_limits){VALIDATION_DEFAULT_RECORDS,
		    VALIDATION_DEFAULT_RUNS, VALIDATION_DEFAULT_LINKS, VALIDATION_DEFAULT_MEMORY,
		    VALIDATION_DEFAULT_READ_CALLS, VALIDATION_DEFAULT_READ_BYTES,
		    VALIDATION_DEFAULT_WORK};
	}
}

static enum ntfs_result
limit_failure(struct validation *v, enum ntfs_validation_limit limit)
{
	if (v->failure == NTFS_OK) {
		v->failure = NTFS_RANGE;
		v->report->exhausted = limit;
	}
	return v->failure;
}

static enum ntfs_result
work(struct validation *v, uint64_t units)
{
	if (v->failure != NTFS_OK) {
		return v->failure;
	}
	if (units > v->limits.max_work_units - v->report->work_units) {
		return limit_failure(v, NTFS_VALIDATION_LIMIT_WORK);
	}
	v->report->work_units += units;
	return NTFS_OK;
}

static void *
validation_allocate(void *context, size_t size)
{
	struct validation *v = context;
	void *memory;

	if (work(v, 1) != NTFS_OK) {
		return NULL;
	}
	if (size > v->limits.max_memory_bytes - v->memory) {
		limit_failure(v, NTFS_VALIDATION_LIMIT_MEMORY);
		return NULL;
	}
	v->report->allocation_calls++;
	memory = v->source.allocate(v->source.context, size);
	if (memory != NULL) {
		v->memory += size;
		if (v->memory > v->report->peak_memory_bytes) {
			v->report->peak_memory_bytes = v->memory;
		}
	}
	return memory;
}

static void
validation_release(void *context, void *memory, size_t size)
{
	struct validation *v = context;

	if (memory != NULL) {
		v->source.release(v->source.context, memory, size);
		v->memory -= size;
	}
}

static enum ntfs_result
validation_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct validation *v = context;

	if (v->failure != NTFS_OK) {
		return v->failure;
	}
	if (v->report->read_calls == v->limits.max_read_calls) {
		return limit_failure(v, NTFS_VALIDATION_LIMIT_READ_CALLS);
	}
	if (size > v->limits.max_read_bytes - v->report->read_bytes) {
		return limit_failure(v, NTFS_VALIDATION_LIMIT_READ_BYTES);
	}
	if (work(v, size) != NTFS_OK) {
		return v->failure;
	}
	v->report->read_calls++;
	v->report->read_bytes += size;
	return v->source.read(v->source.context, offset, bytes, size);
}

static enum ntfs_result
grow(struct validation *v, void **buffer, uint32_t *capacity, uint32_t needed, size_t element_size,
    uint32_t maximum, enum ntfs_validation_limit limit)
{
	void *replacement;
	uint32_t next;

	if (needed > maximum) {
		return limit_failure(v, limit);
	}
	if (needed <= *capacity) {
		return NTFS_OK;
	}
	next = *capacity == 0 ? VALIDATION_VECTOR_START : *capacity;
	while (next < needed && next < maximum) {
		next = next > maximum / VALIDATION_VECTOR_GROWTH ? maximum
								 : next * VALIDATION_VECTOR_GROWTH;
	}
	if (next > maximum) {
		next = maximum;
	}
	if (element_size > SIZE_MAX / next) {
		return limit_failure(v, NTFS_VALIDATION_LIMIT_MEMORY);
	}
	replacement = validation_allocate(v, (size_t)next * element_size);
	if (replacement == NULL) {
		return v->failure != NTFS_OK ? v->failure : NTFS_NO_MEMORY;
	}
	ntfs_zero(replacement, (size_t)next * element_size);
	ntfs_copy(replacement, *buffer, (size_t)*capacity * element_size);
	validation_release(v, *buffer, (size_t)*capacity * element_size);
	*buffer = replacement;
	*capacity = next;
	return NTFS_OK;
}

static struct validation_record *
checked_reference(struct validation *v, uint64_t reference)
{
	uint64_t number = reference & NTFS_REFERENCE_RECORD_MASK;
	struct validation_record *record;

	if (reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 || number >= v->report->record_slots) {
		return NULL;
	}
	record = &v->records[number];
	return record->reference == reference && record->base == 0 ? record : NULL;
}

static bool
inert_reserved_record(const uint8_t *record)
{
	const struct ntfs_disk_record *header = (const void *)record;
	struct ntfs_attr_view attr;
	const uint8_t *value;
	size_t size;
	uint32_t position = ntfs_u16(header->attrs_offset);
	unsigned standard = 0, security = 0, data = 0;
	enum ntfs_result result;

	while (
	    (result = ntfs_attr_at(record, ntfs_u32(header->used), &position, &attr)) == NTFS_OK) {
		if (attr.flags != 0 || attr.disk->name_length != 0 ||
		    ntfs_attr_value(&attr, &value, &size) != NTFS_OK) {
			return false;
		}
		switch (attr.type) {
		case NTFS_ATTR_STANDARD:
			if (++standard != 1) {
				return false;
			}
			break;
		case NTFS_ATTR_SECURITY_DESCRIPTOR:
			if (++security != 1) {
				return false;
			}
			break;
		case NTFS_ATTRIBUTE_DATA:
			if (++data != 1 || size != 0) {
				return false;
			}
			break;
		default:
			return false;
		}
	}
	return result == NTFS_END && standard == 1 && data == 1;
}

static enum ntfs_result
scan_records(struct validation *v)
{
	struct ntfs_node *mft = NULL;
	struct ntfs_stream *bitmap = NULL;
	const struct ntfs_disk_record *header;
	uint8_t *record = NULL, *bits = NULL;
	uint64_t count = v->volume->mft->size / v->volume->info.record_size, bitmap_size, i;
	uint16_t flags;
	uint32_t position;
	struct ntfs_attr_view attr;
	bool allocated;
	enum ntfs_result result;

	v->report->stage = NTFS_VALIDATION_RECORDS;
	v->report->record_slots = count;
	if (v->volume->mft->size % v->volume->info.record_size != 0) {
		return NTFS_CORRUPT;
	}
	if (count == 0 || count > v->limits.max_records) {
		return limit_failure(v, NTFS_VALIDATION_LIMIT_RECORDS);
	}
	if (count > SIZE_MAX / sizeof(*v->records)) {
		return limit_failure(v, NTFS_VALIDATION_LIMIT_MEMORY);
	}
	bitmap_size = (count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE;
	result = ntfs_node_by_number(v->volume, NTFS_MFT_RECORD, &mft);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(mft, NTFS_ATTR_BITMAP, NULL, 0, &bitmap);
	}
	if (result != NTFS_OK) {
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_CORRUPT;
		}
		goto finish;
	}
	if (bitmap->flags != 0 || bitmap->size < bitmap_size || bitmap->initialized < bitmap_size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	bits = validation_allocate(v, (size_t)bitmap_size);
	record = validation_allocate(v, v->volume->info.record_size);
	v->records = validation_allocate(v, (size_t)count * sizeof(*v->records));
	if (bits == NULL || record == NULL || v->records == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	ntfs_zero(v->records, (size_t)count * sizeof(*v->records));
	result = ntfs_stream_exact(bitmap, 0, bits, (size_t)bitmap_size);
	for (i = 0; result == NTFS_OK && i < count; i++) {
		v->report->record_number = i;
		v->report->reference = 0;
		v->report->related_reference = 0;
		result = work(v, v->volume->info.record_size);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(v->volume->mft, i * v->volume->info.record_size,
			    record, v->volume->info.record_size);
		}
		if (result != NTFS_OK) {
			break;
		}
		allocated = (bits[i / NTFS_BITS_PER_BYTE] & (1u << (i % NTFS_BITS_PER_BYTE))) != 0;
		header = (const void *)record;
		flags = ntfs_u16(header->flags);
		if (!allocated) {
			if (ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic)) &&
			    (flags & NTFS_RECORD_IN_USE) != 0) {
				result = NTFS_CORRUPT;
			}
			v->report->records_scanned++;
			continue;
		}
		result = ntfs_record_validate(record, v->volume->info.record_size);
		if (result != NTFS_OK) {
			break;
		}
		v->records[i].reference =
		    i | (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
		v->report->reference = v->records[i].reference;
		v->records[i].base = ntfs_u64(header->base_reference);
		v->records[i].flags = flags;
		v->records[i].links = ntfs_u16(header->links);
		position = ntfs_u16(header->attrs_offset);
		if (i >= VALIDATION_RESERVED_FIRST && i <= VALIDATION_RESERVED_LAST &&
		    flags == NTFS_RECORD_IN_USE && v->records[i].base == 0 &&
		    v->records[i].links == 0) {
			v->records[i].reserved_empty = ntfs_attr_at(record, ntfs_u32(header->used),
							   &position, &attr) == NTFS_END;
			v->records[i].reserved_inert =
			    v->records[i].reserved_empty || inert_reserved_record(record);
		}
		v->report->records_scanned++;
		if (v->records[i].base == 0) {
			v->report->base_records++;
		} else {
			v->report->extension_records++;
		}
	}
	for (i = 0; result == NTFS_OK && i < count; i++) {
		if (v->records[i].reference == 0) {
			continue;
		}
		v->report->reference = v->records[i].reference;
		v->report->record_number = i;
		v->report->related_reference = v->records[i].base;
		if (v->records[i].base != 0 && checked_reference(v, v->records[i].base) == NULL) {
			result = NTFS_STALE;
		}
	}
finish:
	validation_release(v, record, v->volume->info.record_size);
	validation_release(v, bits, (size_t)bitmap_size);
	ntfs_stream_close(bitmap);
	ntfs_node_close(mft);
	return result;
}

static int
compare_runs(struct validation *v, const void *a, const void *b)
{
	const struct validation_run *left = a, *right = b;

	(void)v;
	if (left->first != right->first) {
		return left->first < right->first ? -1 : 1;
	}
	return left->end < right->end ? -1 : left->end != right->end;
}

static int
compare_links(struct validation *v, const void *a, const void *b)
{
	const struct validation_link *left = a, *right = b;
	uint16_t left_unit, right_unit;
	size_t i, length = left->length < right->length ? left->length : right->length;

	if (work(v, (uint64_t)length * sizeof(uint16_t) + sizeof(*left)) != NTFS_OK) {
		return 0;
	}
	if (left->parent != right->parent) {
		return left->parent < right->parent ? -1 : 1;
	}
	if (left->reference != right->reference) {
		return left->reference < right->reference ? -1 : 1;
	}
	if (left->name_namespace != right->name_namespace) {
		return left->name_namespace < right->name_namespace ? -1 : 1;
	}
	for (i = 0; i < length; i++) {
		left_unit = v->names[left->offset + i];
		right_unit = v->names[right->offset + i];
		if (left_unit != right_unit) {
			return left_unit < right_unit ? -1 : 1;
		}
	}
	return left->length < right->length ? -1 : left->length != right->length;
}

static enum ntfs_result
sift(struct validation *v, uint8_t *bytes, size_t stride, uint32_t root, uint32_t count,
    int (*compare)(struct validation *, const void *, const void *))
{
	union {
		struct validation_run run;
		struct validation_link link;
	} temporary;

	uint32_t child;
	int comparison;

	while (root < count / VALIDATION_VECTOR_GROWTH) {
		if (work(v, 1) != NTFS_OK) {
			return v->failure;
		}
		child = root * VALIDATION_VECTOR_GROWTH + 1;
		if (child + 1 < count) {
			comparison = compare(v, bytes + (size_t)child * stride,
			    bytes + (size_t)(child + 1) * stride);
			if (v->failure != NTFS_OK) {
				return v->failure;
			}
			if (comparison < 0) {
				child++;
			}
		}
		comparison =
		    compare(v, bytes + (size_t)root * stride, bytes + (size_t)child * stride);
		if (v->failure != NTFS_OK) {
			return v->failure;
		}
		if (comparison >= 0) {
			break;
		}
		ntfs_copy(&temporary, bytes + (size_t)root * stride, stride);
		ntfs_copy(bytes + (size_t)root * stride, bytes + (size_t)child * stride, stride);
		ntfs_copy(bytes + (size_t)child * stride, &temporary, stride);
		root = child;
	}
	return NTFS_OK;
}

static enum ntfs_result
sort(struct validation *v, void *storage, size_t stride, uint32_t count,
    int (*compare)(struct validation *, const void *, const void *))
{
	union {
		struct validation_run run;
		struct validation_link link;
	} temporary;

	uint8_t *bytes = storage;
	uint32_t i;
	enum ntfs_result result;

	for (i = count / VALIDATION_VECTOR_GROWTH; i != 0; i--) {
		result = sift(v, bytes, stride, i - 1, count, compare);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (i = count; i > 1; i--) {
		ntfs_copy(&temporary, bytes, stride);
		ntfs_copy(bytes, bytes + (size_t)(i - 1) * stride, stride);
		ntfs_copy(bytes + (size_t)(i - 1) * stride, &temporary, stride);
		result = sift(v, bytes, stride, 0, i - 1, compare);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
check_directory_graph(struct validation *v)
{
	struct validation_record *record;
	uint64_t i, next, root_reference;

	if (v->report->record_slots <= NTFS_ROOT_RECORD ||
	    (v->records[NTFS_ROOT_RECORD].flags & NTFS_RECORD_DIRECTORY) == 0) {
		return NTFS_CORRUPT;
	}
	root_reference = v->records[NTFS_ROOT_RECORD].reference;
	if (v->records[NTFS_ROOT_RECORD].primary_names != 1 ||
	    v->records[NTFS_ROOT_RECORD].links != 1) {
		v->report->reference = root_reference;
		v->report->record_number = NTFS_ROOT_RECORD;
		v->report->related_reference = root_reference;
		v->report->attribute_type = NTFS_ATTR_FILENAME;
		return NTFS_CORRUPT;
	}

	for (i = 0; i < v->report->record_slots; i++) {
		record = &v->records[i];
		if (record->reference == 0 || record->base != 0 || record->reserved_inert ||
		    i == NTFS_ROOT_RECORD) {
			continue;
		}
		v->report->reference = record->reference;
		v->report->record_number = i;
		v->report->related_reference = record->parent;
		v->report->attribute_type = NTFS_ATTR_FILENAME;
		v->report->cluster = 0;
		if (record->dos_names) {
			v->report->deferred_dos_link_counts++;
			if (v->deferred_dos_reference == 0) {
				v->deferred_dos_reference = record->reference;
			}
		} else if (record->primary_names != record->links || record->primary_names == 0) {
			return NTFS_CORRUPT;
		}
		if ((record->flags & NTFS_RECORD_DIRECTORY) == 0) {
			continue;
		}
		if (record->parent == 0 || record->primary_names != 1) {
			return NTFS_CORRUPT;
		}
		next = record->reference;
		while (next != root_reference) {
			if (work(v, 1) != NTFS_OK) {
				return v->failure;
			}
			record = checked_reference(v, next);
			if (record == NULL || (record->flags & NTFS_RECORD_DIRECTORY) == 0) {
				return NTFS_CORRUPT;
			}
			if (record->directory_state == VALIDATION_DIRECTORY_VISITED) {
				break;
			}
			if (record->directory_state == VALIDATION_DIRECTORY_VISITING) {
				v->report->related_reference = next;
				return NTFS_CORRUPT;
			}
			record->directory_state = VALIDATION_DIRECTORY_VISITING;
			next = record->parent;
		}
		next = v->records[i].reference;
		while (next != root_reference) {
			if (work(v, 1) != NTFS_OK) {
				return v->failure;
			}
			record = checked_reference(v, next);
			if (record == NULL) {
				return NTFS_CORRUPT;
			}
			if (record->directory_state != VALIDATION_DIRECTORY_VISITING) {
				break;
			}
			record->directory_state = VALIDATION_DIRECTORY_VISITED;
			next = record->parent;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
scan_namespace(struct validation *v)
{
	struct ntfs_node *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_dirent entry;
	const struct validation_link *first, *second;
	uint64_t i;
	int comparison;
	enum ntfs_result result = NTFS_OK;

	v->report->stage = NTFS_VALIDATION_NAMESPACE;
	v->report->attribute_type = NTFS_ATTR_INDEX_ROOT;
	v->report->related_reference = 0;
	for (i = 0; i < v->report->record_slots; i++) {
		if (v->records[i].reference == 0 || v->records[i].base != 0 ||
		    (v->records[i].flags & NTFS_RECORD_DIRECTORY) == 0) {
			continue;
		}
		v->report->reference = v->records[i].reference;
		v->report->record_number = i;
		result = ntfs_node_open(v->volume, v->records[i].reference, &node);
		if (result == NTFS_OK) {
			result = ntfs_directory_open(node, &directory);
		}
		if (result != NTFS_OK) {
			break;
		}
		while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
			if (work(v, sizeof(entry)) != NTFS_OK) {
				result = v->failure;
				break;
			}
			result =
			    remember_link(v, entry.parent_reference, entry.reference, entry.name,
				entry.name_length, entry.name_namespace, VALIDATION_INDEX_SOURCE);
			if (result != NTFS_OK) {
				break;
			}
		}
		ntfs_directory_close(directory);
		directory = NULL;
		ntfs_node_close(node);
		node = NULL;
		if (result != NTFS_END) {
			break;
		}
		v->report->directories++;
		result = NTFS_OK;
	}
	ntfs_directory_close(directory);
	ntfs_node_close(node);
	if (result != NTFS_OK) {
		return result;
	}
	result = sort(v, v->links, sizeof(*v->links), v->link_count, compare_links);
	if (result != NTFS_OK) {
		return result;
	}
	for (i = 0; i < v->link_count; i += VALIDATION_LINK_PAIR) {
		first = &v->links[i];
		v->report->reference = first->reference;
		v->report->record_number = first->reference & NTFS_REFERENCE_RECORD_MASK;
		v->report->related_reference = first->parent;
		v->report->attribute_type = NTFS_ATTR_FILENAME;
		if (i + 1 == v->link_count) {
			return NTFS_CORRUPT;
		}
		second = &v->links[i + 1];
		comparison = compare_links(v, first, second);
		if (v->failure != NTFS_OK) {
			return v->failure;
		}
		if (comparison != 0 || first->source == second->source) {
			return NTFS_CORRUPT;
		}
		if (i + VALIDATION_LINK_PAIR < v->link_count) {
			comparison = compare_links(v, first, &v->links[i + VALIDATION_LINK_PAIR]);
			if (v->failure != NTFS_OK) {
				return v->failure;
			}
			if (comparison == 0) {
				return NTFS_CORRUPT;
			}
		}
	}
	return check_directory_graph(v);
}

static enum ntfs_result
scan_allocation(struct validation *v)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *bitmap = NULL;
	uint8_t *bytes = NULL;
	const struct validation_run *run;
	uint64_t count = v->volume->info.cluster_count, bitmap_size, offset, cluster;
	uint32_t i, current = 0;
	size_t take, byte;
	unsigned bit;
	bool allocated, claimed;
	enum ntfs_result result;

	v->report->stage = NTFS_VALIDATION_ALLOCATION;
	v->report->reference = 0;
	v->report->related_reference = 0;
	v->report->attribute_type = NTFS_ATTRIBUTE_DATA;
	result = sort(v, v->runs, sizeof(*v->runs), v->run_count, compare_runs);
	if (result != NTFS_OK) {
		return result;
	}
	for (i = 1; i < v->run_count; i++) {
		if (v->runs[i - 1].end > v->runs[i].first) {
			v->report->reference = v->runs[i].reference;
			v->report->record_number =
			    v->runs[i].reference & NTFS_REFERENCE_RECORD_MASK;
			v->report->related_reference = v->runs[i - 1].reference;
			v->report->attribute_type = v->runs[i].type;
			v->report->cluster = v->runs[i].first;
			return NTFS_CORRUPT;
		}
	}
	bitmap_size = (count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE;
	v->report->record_number = NTFS_BITMAP_RECORD;
	result = ntfs_node_by_number(v->volume, NTFS_BITMAP_RECORD, &node);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, &bitmap);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (bitmap->flags != 0 || bitmap->size < bitmap_size || bitmap->initialized < bitmap_size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	bytes = validation_allocate(v, NTFS_BITMAP_SCAN_BYTES);
	if (bytes == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	for (offset = 0; offset < bitmap_size; offset += take) {
		take = bitmap_size - offset < NTFS_BITMAP_SCAN_BYTES
		    ? (size_t)(bitmap_size - offset)
		    : NTFS_BITMAP_SCAN_BYTES;
		result = work(v, (uint64_t)take * NTFS_BITS_PER_BYTE);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(bitmap, offset, bytes, take);
		}
		if (result != NTFS_OK) {
			break;
		}
		for (byte = 0; byte < take; byte++) {
			for (bit = 0; bit < NTFS_BITS_PER_BYTE; bit++) {
				cluster = (offset + byte) * NTFS_BITS_PER_BYTE + bit;
				if (cluster >= count) {
					break;
				}
				while (current < v->run_count && v->runs[current].end <= cluster) {
					current++;
				}
				run = current < v->run_count ? &v->runs[current] : NULL;
				claimed = run != NULL && run->first <= cluster;
				allocated = (bytes[byte] & (1u << bit)) != 0;
				if (allocated) {
					v->report->allocated_clusters++;
					if (!claimed) {
						v->report->unclaimed_clusters++;
						v->report->cluster = cluster;
					}
				} else if (claimed) {
					v->report->reference = run->reference;
					v->report->record_number =
					    run->reference & NTFS_REFERENCE_RECORD_MASK;
					v->report->attribute_type = run->type;
					v->report->cluster = cluster;
					result = NTFS_CORRUPT;
					goto finish;
				}
			}
		}
	}
	if (result == NTFS_OK && v->report->unclaimed_clusters != 0) {
		result = NTFS_CORRUPT;
	}
finish:
	validation_release(v, bytes, NTFS_BITMAP_SCAN_BYTES);
	ntfs_stream_close(bitmap);
	ntfs_node_close(node);
	return result;
}

enum ntfs_result
ntfs_validate(const struct ntfs_environment *environment, const struct ntfs_limits *core_limits,
    const struct ntfs_validation_limits *limits, struct ntfs_validation_report *report)
{
	struct validation v = {0};
	struct ntfs_environment bounded;
	enum ntfs_result result;

	if (report == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	report->result = NTFS_INVALID;
	if (environment == NULL || environment->api_version != NTFS_API_VERSION ||
	    environment->allocate == NULL || environment->release == NULL ||
	    environment->read == NULL) {
		return NTFS_INVALID;
	}
	v.source = *environment;
	v.report = report;
	ntfs_validation_default_limits(&v.limits);
	if (limits != NULL) {
		v.limits = *limits;
	}
	if (v.limits.max_records == 0 || v.limits.max_records > VALIDATION_DEFAULT_RECORDS ||
	    v.limits.max_runs == 0 || v.limits.max_runs > VALIDATION_DEFAULT_RUNS ||
	    v.limits.max_links == 0 || v.limits.max_links > VALIDATION_DEFAULT_LINKS ||
	    v.limits.max_memory_bytes == 0 || v.limits.max_read_calls == 0 ||
	    v.limits.max_read_bytes == 0 || v.limits.max_work_units == 0) {
		return NTFS_INVALID;
	}
	bounded = (struct ntfs_environment){NTFS_API_VERSION, &v, environment->size_bytes,
	    validation_read, validation_allocate, validation_release};
	report->stage = NTFS_VALIDATION_MOUNT;
	result = ntfs_mount(&bounded, core_limits, &v.volume);
	if (result == NTFS_OK) {
		result = scan_records(&v);
	}
	if (result == NTFS_OK) {
		result = scan_attributes(&v);
	}
	if (result == NTFS_OK) {
		result = scan_namespace(&v);
	}
	if (result == NTFS_OK) {
		result = scan_allocation(&v);
	}
	if (result == NTFS_OK && report->deferred_dos_link_counts != 0) {
		result = NTFS_UNSUPPORTED;
		report->stage = NTFS_VALIDATION_NAMESPACE;
		report->reference = v.deferred_dos_reference;
		report->record_number = v.deferred_dos_reference & NTFS_REFERENCE_RECORD_MASK;
		report->related_reference = 0;
		report->attribute_type = NTFS_ATTR_FILENAME;
		report->cluster = 0;
	}
	validation_release(&v, v.names, (size_t)v.name_capacity * sizeof(*v.names));
	validation_release(&v, v.links, (size_t)v.link_capacity * sizeof(*v.links));
	validation_release(&v, v.runs, (size_t)v.run_capacity * sizeof(*v.runs));
	validation_release(&v, v.records, (size_t)report->record_slots * sizeof(*v.records));
	if (v.volume != NULL) {
		enum ntfs_result cleanup = ntfs_unmount(v.volume);

		if (cleanup != NTFS_OK) {
			result = cleanup;
		}
	}
	if (v.memory != 0) {
		result = NTFS_CORRUPT;
	}
	if (v.failure != NTFS_OK) {
		result = v.failure;
	}
	report->result = result;
	if (result == NTFS_OK) {
		report->stage = NTFS_VALIDATION_FINISHED;
		report->complete = true;
		report->reference = 0;
		report->record_number = 0;
		report->related_reference = 0;
		report->attribute_type = 0;
		report->cluster = 0;
	}
	return result;
}

static enum ntfs_result
remember_stream(struct validation *v, struct ntfs_stream *stream, uint64_t reference, uint32_t type)
{
	const struct ntfs_run *run;
	void *storage;
	uint32_t i;
	enum ntfs_result result;

	for (i = 0; i < stream->run_count; i++) {
		run = &stream->runs[i];
		if (work(v, sizeof(*run)) != NTFS_OK) {
			return v->failure;
		}
		if (run->lcn == NTFS_HOLE) {
			continue;
		}
		storage = v->runs;
		result = grow(v, &storage, &v->run_capacity, v->run_count + 1, sizeof(*v->runs),
		    v->limits.max_runs, NTFS_VALIDATION_LIMIT_RUNS);
		if (result != NTFS_OK) {
			return result;
		}
		v->runs = storage;
		if (run->length > UINT64_MAX - v->report->claimed_clusters) {
			return NTFS_CORRUPT;
		}
		v->runs[v->run_count++] =
		    (struct validation_run){run->lcn, run->lcn + run->length, reference, type};
		v->report->physical_runs++;
		v->report->claimed_clusters += run->length;
	}
	v->report->streams++;
	return NTFS_OK;
}

static enum ntfs_result
remember_link(struct validation *v, uint64_t parent, uint64_t reference, const uint16_t *name,
    uint16_t length, uint8_t name_namespace, uint8_t source)
{
	struct validation_record *owner = checked_reference(v, reference);
	struct validation_record *directory = checked_reference(v, parent);
	void *storage;
	enum ntfs_result result;
	size_t i;

	v->report->reference = reference;
	v->report->record_number = reference & NTFS_REFERENCE_RECORD_MASK;
	v->report->related_reference = parent;
	if (owner == NULL || directory == NULL) {
		return NTFS_STALE;
	}
	if ((directory->flags & NTFS_RECORD_DIRECTORY) == 0 || length == 0 ||
	    length > NTFS_NAME_MAX || name_namespace > NTFS_NAMESPACE_WIN32_DOS) {
		return NTFS_CORRUPT;
	}
	for (i = 0; i < length; i++) {
		if (name[i] == 0 || name[i] == '/') {
			return NTFS_CORRUPT;
		}
	}
	/* The root's self-name is a structural anchor, not a namespace edge. */
	if ((reference & NTFS_REFERENCE_RECORD_MASK) == NTFS_ROOT_RECORD) {
		if (parent != reference || length != 1 || name[0] != '.') {
			return NTFS_CORRUPT;
		}
		if (source == VALIDATION_FILENAME_SOURCE && ++owner->primary_names != 1) {
			return NTFS_CORRUPT;
		}
		return NTFS_OK;
	}
	storage = v->links;
	result = grow(v, &storage, &v->link_capacity, v->link_count + 1, sizeof(*v->links),
	    v->limits.max_links, NTFS_VALIDATION_LIMIT_LINKS);
	if (result == NTFS_OK) {
		v->links = storage;
		storage = v->names;
		result =
		    grow(v, &storage, &v->name_capacity, v->name_count + length, sizeof(*v->names),
			v->limits.max_links * NTFS_NAME_MAX, NTFS_VALIDATION_LIMIT_LINKS);
	}
	if (result != NTFS_OK) {
		return result;
	}
	v->names = storage;
	ntfs_copy(v->names + v->name_count, name, (size_t)length * sizeof(*name));
	v->links[v->link_count++] = (struct validation_link){
	    parent, reference, v->name_count, length, name_namespace, source};
	v->name_count += length;
	if (source == VALIDATION_FILENAME_SOURCE) {
		if (name_namespace == NTFS_NAMESPACE_DOS) {
			owner->dos_names = true;
		} else {
			owner->primary_names++;
			if ((owner->flags & NTFS_RECORD_DIRECTORY) != 0) {
				if (owner->parent != 0 && owner->parent != parent) {
					return NTFS_CORRUPT;
				}
				owner->parent = parent;
			}
		}
		v->report->filename_attributes++;
	} else {
		v->report->index_entries++;
	}
	return NTFS_OK;
}

static enum ntfs_result
filename(struct validation *v, uint64_t owner, const struct ntfs_attr_view *attr)
{
	const struct ntfs_disk_filename *file;
	const uint8_t *value;
	uint16_t name[NTFS_NAME_MAX];
	size_t size, i;
	enum ntfs_result result;

	result = ntfs_attr_value(attr, &value, &size);
	if (result != NTFS_OK || attr->flags != 0 || attr->disk->name_length != 0 ||
	    size < sizeof(*file)) {
		return NTFS_CORRUPT;
	}
	file = (const void *)value;
	if (size != sizeof(*file) + (size_t)file->length * NTFS_UTF16_UNIT_BYTES) {
		return NTFS_CORRUPT;
	}
	for (i = 0; i < file->length; i++) {
		name[i] = ntfs_u16(value + sizeof(*file) + i * NTFS_UTF16_UNIT_BYTES);
	}
	return remember_link(v, ntfs_u64(file->parent), owner, name, file->length,
	    file->name_namespace, VALIDATION_FILENAME_SOURCE);
}

static enum ntfs_result
check_list(struct validation *v, struct ntfs_node *owner, const uint8_t *bytes, size_t size)
{
	const struct ntfs_disk_attr_list *entry;
	const struct validation_record *record;
	struct ntfs_attr_view attr;
	uint8_t *loaded = NULL;
	uint16_t name[NTFS_NAME_MAX];
	uint64_t reference, number;
	size_t offset = 0, i;
	enum ntfs_result result;

	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		if (work(v, ntfs_u16(entry->length)) != NTFS_OK) {
			return v->failure;
		}
		reference = ntfs_u64(entry->reference);
		number = reference & NTFS_REFERENCE_RECORD_MASK;
		v->report->related_reference = reference;
		if (number >= v->report->record_slots ||
		    reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
			return NTFS_STALE;
		}
		record = &v->records[number];
		if (record->reference != reference ||
		    (reference != owner->reference && record->base != owner->reference)) {
			return NTFS_STALE;
		}
		for (i = 0; i < entry->name_length; i++) {
			name[i] = ntfs_u16((const uint8_t *)entry + entry->name_offset +
			    i * NTFS_UTF16_UNIT_BYTES);
		}
		if (reference == owner->reference) {
			loaded = owner->record;
			result = NTFS_OK;
		} else {
			result = ntfs_record_read(v->volume, number, &loaded);
		}
		if (result == NTFS_OK) {
			result = ntfs_listed_attribute(loaded, ntfs_u32(entry->type), name,
			    entry->name_length, ntfs_u16(entry->instance), ntfs_u64(entry->lowest),
			    &attr);
		}
		if (loaded != owner->record) {
			ntfs_free(v->volume, loaded, v->volume->info.record_size);
		}
		loaded = NULL;
		if (result != NTFS_OK) {
			return result;
		}
	}
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
listed_extent(struct validation *v, const uint8_t *bytes, size_t size, uint64_t reference,
    const struct ntfs_attr_view *attr, uint64_t lowest)
{
	const struct ntfs_disk_attr_list *entry;
	size_t offset = 0;
	bool found = false;
	enum ntfs_result result;

	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		if (work(v, ntfs_u16(entry->length)) != NTFS_OK) {
			return v->failure;
		}
		if (ntfs_u64(entry->reference) != reference ||
		    ntfs_u32(entry->type) != attr->type || ntfs_u64(entry->lowest) != lowest ||
		    entry->name_length != attr->disk->name_length ||
		    (lowest == 0 && ntfs_u16(entry->instance) != attr->instance)) {
			continue;
		}
		if (!ntfs_equal((const uint8_t *)entry + entry->name_offset,
			attr->bytes + ntfs_u16(attr->disk->name_offset),
			(size_t)entry->name_length * NTFS_UTF16_UNIT_BYTES)) {
			continue;
		}
		if (found) {
			return NTFS_CORRUPT;
		}
		found = true;
	}
	if (result != NTFS_END) {
		return result;
	}
	return found ? NTFS_OK : NTFS_CORRUPT;
}

static enum ntfs_result
scan_attributes(struct validation *v)
{
	struct ntfs_node *owner = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	const struct ntfs_disk_record *header;
	const struct ntfs_disk_nonresident *extent;
	struct ntfs_attr_view attr, unique;
	uint8_t *record = NULL, *list = NULL;
	uint16_t name[NTFS_NAME_MAX];
	uint64_t i, owner_reference, lowest;
	uint32_t position;
	size_t list_size = 0, unit;
	enum ntfs_result result = NTFS_OK;

	v->report->stage = NTFS_VALIDATION_ATTRIBUTES;
	for (i = 0; i < v->report->record_slots; i++) {
		if (v->records[i].reference == 0 || v->records[i].reserved_empty) {
			continue;
		}
		v->report->reference = v->records[i].reference;
		v->report->record_number = i;
		v->report->related_reference = 0;
		v->report->attribute_type = 0;
		owner_reference =
		    v->records[i].base != 0 ? v->records[i].base : v->records[i].reference;
		result = ntfs_node_open(v->volume, owner_reference, &owner);
		if (result == NTFS_OK) {
			result = ntfs_node_metadata(owner, &stat);
			if (result == NTFS_NOT_FOUND) {
				result = NTFS_CORRUPT;
			}
		}
		if (result != NTFS_OK) {
			break;
		}
		list_size = 0;
		result = ntfs_attribute_list_read(owner, &list, &list_size);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		} else if (result == NTFS_OK && v->records[i].base == 0) {
			result = check_list(v, owner, list, list_size);
		}
		if (result != NTFS_OK) {
			break;
		}
		if (v->records[i].base == 0) {
			record = owner->record;
		} else {
			result = ntfs_record_read(v->volume, i, &record);
		}
		if (result != NTFS_OK) {
			break;
		}
		header = (const void *)record;
		position = ntfs_u16(header->attrs_offset);
		while ((result = ntfs_attr_at(record, ntfs_u32(header->used), &position, &attr)) ==
		    NTFS_OK) {
			v->report->attribute_type = attr.type;
			v->report->related_reference = owner_reference;
			if (work(v, attr.length) != NTFS_OK) {
				result = v->failure;
				break;
			}
			lowest = 0;
			if (attr.disk->nonresident) {
				extent = (const void *)(attr.bytes + sizeof(struct ntfs_disk_attr));
				lowest = ntfs_u64(extent->lowest);
			}
			if (v->records[i].base != 0 || lowest != 0 ||
			    (list != NULL && attr.type != NTFS_ATTR_LIST)) {
				result = listed_extent(
				    v, list, list_size, v->records[i].reference, &attr, lowest);
				if (result != NTFS_OK) {
					break;
				}
			}
			v->report->attributes++;
			if (attr.type == NTFS_ATTR_FILENAME) {
				result = filename(v, owner_reference, &attr);
			} else if (lowest == 0) {
				for (unit = 0; unit < attr.disk->name_length; unit++) {
					name[unit] =
					    ntfs_u16(attr.bytes + ntfs_u16(attr.disk->name_offset) +
						unit * NTFS_UTF16_UNIT_BYTES);
				}
				result = ntfs_bad_clusters_from_attr(owner, &attr, &stream);
				if (result == NTFS_NOT_FOUND) {
					result = ntfs_attribute_open(owner, attr.type, name,
					    attr.disk->name_length, &stream);
				} else if (result == NTFS_OK && list != NULL) {
					/* Listed bad-cluster continuations need their own complete
					 * inventory contract; never omit them from the verdict. */
					result = NTFS_UNSUPPORTED;
				} else if (result == NTFS_OK) {
					result = ntfs_attr_find(owner->record,
					    v->volume->info.record_size, attr.type, name,
					    attr.disk->name_length, UINT16_MAX, &unique);
				}
				if (result == NTFS_OK) {
					if (!stream->resident) {
						result = remember_stream(
						    v, stream, owner_reference, attr.type);
					}
				}
				ntfs_stream_close(stream);
				stream = NULL;
			}
			if (result != NTFS_OK) {
				break;
			}
		}
		if (result == NTFS_END) {
			result = NTFS_OK;
		}
		if (record != owner->record) {
			ntfs_free(v->volume, record, v->volume->info.record_size);
		}
		record = NULL;
		ntfs_free(v->volume, list, list_size);
		list = NULL;
		ntfs_node_close(owner);
		owner = NULL;
		if (result != NTFS_OK) {
			break;
		}
	}
	if (owner != NULL && record != owner->record) {
		ntfs_free(v->volume, record, v->volume->info.record_size);
	}
	ntfs_free(v->volume, list, list_size);
	ntfs_node_close(owner);
	return result;
}
