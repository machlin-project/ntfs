/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
/* Darwin exposes its process-RSS rusage field outside strict POSIX mode. */
#define _DARWIN_C_SOURCE 1
#endif
#include <ntfs/ntfs.h>
#include "image.h"
#include "path.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

enum {
	WORKLOAD_DEFAULT_OPERATIONS = 1000,
	WORKLOAD_MAX_OPERATIONS = 1000000,
	WORKLOAD_DEFAULT_REQUEST = 65536,
	WORKLOAD_MAX_REQUEST = 1048576,
	WORKLOAD_MAX_READERS = 64,
	WORKLOAD_MAX_POSITIONS = 1000000,
	WORKLOAD_MEMORY_IMAGE_LIMIT = 256 * 1048576,
	WORKLOAD_CORE_MEMORY_LIMIT = 64 * 1048576,
	WORKLOAD_SAMPLE_BYTES = 64,
	PERCENTILE_DENOMINATOR = 100,
	PERCENTILE_MEDIAN = 50,
	PERCENTILE_TAIL = 95,
	PERCENTILE_EXTREME = 99,
	DECIMAL_RADIX = 10,
	KIBIBYTE_BYTES = 1024,
	WORD_BITS = sizeof(uint32_t) * CHAR_BIT
};

#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)
/* Numerical Recipes LCG, expanded into deterministic 64-bit offsets. */
#define RANDOM_MULTIPLIER UINT32_C(1664525)
#define RANDOM_INCREMENT UINT32_C(1013904223)
#define RANDOM_SEED UINT32_C(0x85a7f12d)

#ifdef CLOCK_MONOTONIC_RAW
/* Darwin's ordinary monotonic clock rounds short calls to microseconds. */
#define WORKLOAD_WALL_CLOCK CLOCK_MONOTONIC_RAW
#define WORKLOAD_WALL_CLOCK_NAME "monotonic raw"
#else
#define WORKLOAD_WALL_CLOCK CLOCK_MONOTONIC
#define WORKLOAD_WALL_CLOCK_NAME "monotonic"
#endif

enum profile {
	READ_SEQUENTIAL,
	READ_RANDOM,
	READ_STRIDED,
	OPEN_STREAM,
	LOOKUP,
	DIRECTORY_NEXT,
	DIRECTORY_SCAN
};

struct measured_device {
	struct ntfs_image image;
	uint8_t *memory_image;
	size_t live_bytes, peak_bytes;
	uint64_t allocations;
};

union allocation_header {
	max_align_t alignment;
	size_t bytes;
};

struct options {
	enum profile profile;
	const char *profile_name;
	size_t operations, warmup_operations, request, readers, stride, positions;
	uint32_t cache_entries;
	bool memory_backend;
	const char *stream_name;
};

struct shared_workload {
	struct ntfs_volume *volume;
	struct ntfs_node *node, *parent;
	uint16_t name[NTFS_NAME_MAX], stream_name[NTFS_NAME_MAX];
	size_t name_units, stream_units;
	struct options options;
	pthread_mutex_t core_lock, start_lock;
	pthread_cond_t start_condition;
	bool started;
};

struct worker {
	struct shared_workload *shared;
	struct ntfs_stream *stream;
	struct ntfs_directory *directory;
	uint8_t *buffer;
	uint64_t *samples;
	size_t operations, position;
	uint64_t bytes, entries, sampled_sum, offset;
	uint32_t random;
	enum ntfs_result result;
};

static uint64_t
now(clockid_t clock)
{
	struct timespec value;

	if (clock_gettime(clock, &value) != 0) {
		abort();
	}
	return (uint64_t)value.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)value.tv_nsec;
}

static uint64_t
random_offset(struct worker *worker)
{
	uint64_t high;

	worker->random = worker->random * RANDOM_MULTIPLIER + RANDOM_INCREMENT;
	high = (uint64_t)worker->random << WORD_BITS;
	worker->random = worker->random * RANDOM_MULTIPLIER + RANDOM_INCREMENT;
	return high | worker->random;
}

static void *
allocate(void *context, size_t size)
{
	struct measured_device *device = context;
	union allocation_header *header;

	if (size > WORKLOAD_CORE_MEMORY_LIMIT - device->live_bytes) {
		return NULL;
	}
	header = malloc(sizeof(*header) + size);
	if (header == NULL) {
		return NULL;
	}
	header->bytes = size;
	device->allocations++;
	device->live_bytes += size;
	if (device->live_bytes > device->peak_bytes) {
		device->peak_bytes = device->live_bytes;
	}
	return header + 1;
}

static void
release(void *context, void *memory, size_t size)
{
	struct measured_device *device = context;
	union allocation_header *header = (union allocation_header *)memory - 1;

	if (header->bytes != size || size > device->live_bytes) {
		abort();
	}
	device->live_bytes -= size;
	free(header);
}

static enum ntfs_result
read_device(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct measured_device *device = context;
	const struct ntfs_environment *base = &device->image.environment;

	if (offset > base->size_bytes || bytes > base->size_bytes - offset) {
		return NTFS_IO;
	}
	if (device->memory_image != NULL) {
		memcpy(buffer, device->memory_image + offset, bytes);
		return NTFS_OK;
	}
	return base->read(base->context, offset, buffer, bytes);
}

static bool
number(const char *text, size_t maximum, size_t *value)
{
	char *end;
	unsigned long long parsed;

	if (*text < '0' || *text > '9') {
		return false;
	}
	errno = 0;
	parsed = strtoull(text, &end, DECIMAL_RADIX);
	if (errno != 0 || *end != 0 || parsed > maximum) {
		return false;
	}
	*value = (size_t)parsed;
	return true;
}

static bool
parse_options(int argc, char **argv, struct options *options)
{
	struct ntfs_limits limits;
	const char *key, *value;
	size_t i, count;

	ntfs_default_limits(&limits);
	*options = (struct options){.profile = READ_SEQUENTIAL,
	    .profile_name = "sequential",
	    .operations = WORKLOAD_DEFAULT_OPERATIONS,
	    .request = WORKLOAD_DEFAULT_REQUEST,
	    .readers = 1,
	    .cache_entries = limits.record_cache_entries,
	    .stream_name = ""};
	for (i = 3; i < (size_t)argc; i += 2) {
		if (i + 1 >= (size_t)argc) {
			return false;
		}
		key = argv[i];
		value = argv[i + 1];
		if (strcmp(key, "--profile") == 0) {
			options->profile_name = value;
			if (strcmp(value, "sequential") == 0) {
				options->profile = READ_SEQUENTIAL;
			} else if (strcmp(value, "random") == 0) {
				options->profile = READ_RANDOM;
			} else if (strcmp(value, "strided") == 0) {
				options->profile = READ_STRIDED;
			} else if (strcmp(value, "open") == 0) {
				options->profile = OPEN_STREAM;
			} else if (strcmp(value, "lookup") == 0) {
				options->profile = LOOKUP;
			} else if (strcmp(value, "directory-next") == 0) {
				options->profile = DIRECTORY_NEXT;
			} else if (strcmp(value, "directory-scan") == 0) {
				options->profile = DIRECTORY_SCAN;
			} else {
				return false;
			}
		} else if (strcmp(key, "--backend") == 0) {
			if (strcmp(value, "memory") == 0) {
				options->memory_backend = true;
			} else if (strcmp(value, "posix") == 0) {
				options->memory_backend = false;
			} else {
				return false;
			}
		} else if (strcmp(key, "--stream") == 0) {
			options->stream_name = value;
		} else if (strcmp(key, "--operations") == 0) {
			if (!number(value, WORKLOAD_MAX_OPERATIONS, &options->operations) ||
			    options->operations == 0) {
				return false;
			}
		} else if (strcmp(key, "--warmup-operations") == 0) {
			if (!number(value, WORKLOAD_MAX_OPERATIONS, &options->warmup_operations)) {
				return false;
			}
		} else if (strcmp(key, "--request") == 0) {
			if (!number(value, WORKLOAD_MAX_REQUEST, &options->request) ||
			    options->request == 0) {
				return false;
			}
		} else if (strcmp(key, "--readers") == 0) {
			if (!number(value, WORKLOAD_MAX_READERS, &options->readers) ||
			    options->readers == 0) {
				return false;
			}
		} else if (strcmp(key, "--cache-entries") == 0) {
			/* Public mount validation owns the configured-cache maximum. */
			if (!number(value, UINT32_MAX, &count)) {
				return false;
			}
			options->cache_entries = (uint32_t)count;
		} else if (strcmp(key, "--stride") == 0) {
			if (!number(value, SIZE_MAX, &options->stride) || options->stride == 0) {
				return false;
			}
		} else if (strcmp(key, "--positions") == 0) {
			if (!number(value, WORKLOAD_MAX_POSITIONS, &options->positions) ||
			    options->positions == 0) {
				return false;
			}
		} else {
			return false;
		}
	}
	return options->readers <= options->operations &&
	    (options->profile == READ_STRIDED ? options->stride != 0 && options->positions != 0
					      : options->stride == 0 && options->positions == 0);
}

static enum ntfs_result
one_operation(struct worker *worker, size_t *read_bytes)
{
	struct shared_workload *shared = worker->shared;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	struct ntfs_dirent entry;
	uint64_t size, maximum;
	enum ntfs_result result;

	*read_bytes = 0;
	switch (shared->options.profile) {
	case READ_RANDOM:
	case READ_SEQUENTIAL:
	case READ_STRIDED:
		size = ntfs_stream_size(worker->stream);
		if (shared->options.profile == READ_STRIDED) {
			worker->offset = (uint64_t)worker->position * shared->options.stride;
		} else if (shared->options.profile == READ_RANDOM) {
			maximum =
			    size > shared->options.request ? size - shared->options.request : 0;
			worker->offset = random_offset(worker) % (maximum + 1);
		}
		result = ntfs_stream_read(worker->stream, worker->offset, worker->buffer,
		    shared->options.request, read_bytes);
		if (result == NTFS_OK) {
			if (shared->options.profile == READ_STRIDED) {
				worker->position++;
				if (worker->position == shared->options.positions) {
					worker->position = 0;
				}
			} else {
				worker->offset += *read_bytes;
				if (worker->offset >= size) {
					worker->offset = 0;
				}
			}
		}
		return result;
	case OPEN_STREAM:
		result = ntfs_stream_open(
		    shared->node, shared->stream_name, shared->stream_units, &stream);
		if (result == NTFS_OK) {
			worker->sampled_sum += ntfs_stream_size(stream);
		}
		ntfs_stream_close(stream);
		return result;
	case LOOKUP:
		result = ntfs_lookup(shared->parent, shared->name, shared->name_units, &node);
		if (result == NTFS_OK) {
			result = ntfs_node_stat(node, &stat);
		}
		if (result == NTFS_OK) {
			worker->sampled_sum += stat.reference;
		}
		ntfs_node_close(node);
		return result;
	case DIRECTORY_NEXT:
		result = ntfs_directory_next(worker->directory, &entry);
		if (result == NTFS_END) {
			ntfs_directory_close(worker->directory);
			worker->directory = NULL;
			result = ntfs_directory_open(shared->node, &worker->directory);
			if (result == NTFS_OK) {
				result = ntfs_directory_next(worker->directory, &entry);
			}
		}
		if (result == NTFS_OK) {
			worker->sampled_sum += entry.reference + entry.name_length;
			worker->entries++;
		}
		return result == NTFS_END ? NTFS_OK : result;
	case DIRECTORY_SCAN:
		result = ntfs_directory_open(shared->node, &worker->directory);
		if (result != NTFS_OK) {
			return result;
		}
		while ((result = ntfs_directory_next(worker->directory, &entry)) == NTFS_OK) {
			worker->sampled_sum += entry.reference + entry.name_length;
			worker->entries++;
		}
		ntfs_directory_close(worker->directory);
		worker->directory = NULL;
		return result == NTFS_END ? NTFS_OK : result;
	}
	return NTFS_INVALID;
}

static void *
run_worker(void *context)
{
	struct worker *worker = context;
	struct shared_workload *shared = worker->shared;
	uint64_t start;
	size_t i, count, sample, j;

	pthread_mutex_lock(&shared->start_lock);
	while (!shared->started) {
		pthread_cond_wait(&shared->start_condition, &shared->start_lock);
	}
	pthread_mutex_unlock(&shared->start_lock);
	for (i = 0; i < worker->operations; i++) {
		start = now(WORKLOAD_WALL_CLOCK);
		pthread_mutex_lock(&shared->core_lock);
		worker->result = one_operation(worker, &count);
		pthread_mutex_unlock(&shared->core_lock);
		worker->samples[i] = now(WORKLOAD_WALL_CLOCK) - start;
		if (worker->result != NTFS_OK) {
			break;
		}
		worker->bytes += count;
		/* Sample outside the timed operation. Full hashes are checked by the
		 * corpus/oracle harness, not by a hash loop inside a throughput test. */
		sample = count < WORKLOAD_SAMPLE_BYTES ? count : WORKLOAD_SAMPLE_BYTES;
		for (j = 0; j < sample; j++) {
			worker->sampled_sum += worker->buffer[j];
		}
	}
	return NULL;
}

static int
compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;

	return a < b ? -1 : a > b ? 1 : 0;
}

static uint64_t
percentile(const uint64_t *sorted, size_t count, unsigned percentile)
{
	size_t rank = (count * percentile + PERCENTILE_DENOMINATOR - 1) / PERCENTILE_DENOMINATOR;

	return sorted[rank - 1];
}

int
main(int argc, char **argv)
{
	struct measured_device device = {.image = {.fd = -1}};
	struct shared_workload shared = {0};
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	struct ntfs_io_statistics before, after;
	struct options options;
	struct worker *workers = NULL;
	pthread_t *threads = NULL;
	uint64_t *samples = NULL;
	struct rusage usage;
	struct timespec resolution;
	uint64_t start, elapsed, cpu_start, cpu, bytes = 0, entries = 0, sum = 0, allocations;
	size_t i, j, warmup, count, created = 0, sample_offset = 0, image_bytes;
	enum ntfs_result result = NTFS_INVALID;
	bool core_lock_initialized = false, start_lock_initialized = false;
	bool condition_initialized = false, measured = false;
	int error;

	if (argc < 3 || !parse_options(argc, argv, &options)) {
		fprintf(stderr,
		    "usage: ntfs-workload IMAGE PATH [--profile "
		    "sequential|random|strided|open|lookup|directory-next|directory-scan]\n"
		    "       [--backend posix|memory] [--operations N] [--request BYTES] [--readers "
		    "N]\n"
		    "       [--warmup-operations N] [--cache-entries N] [--stream NAME]\n"
		    "       [--stride BYTES --positions N] (required only for strided)\n");
		return 2;
	}
	error = ntfs_image_open(argv[1], &device.image);
	if (error != 0) {
		fprintf(stderr, "image: %s\n", strerror(error));
		return 1;
	}
	if (options.memory_backend) {
		if (device.image.environment.size_bytes > WORKLOAD_MEMORY_IMAGE_LIMIT) {
			result = NTFS_RANGE;
			goto finish;
		}
		image_bytes = (size_t)device.image.environment.size_bytes;
		device.memory_image = malloc(image_bytes);
		if (device.memory_image == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
		result = device.image.environment.read(
		    device.image.environment.context, 0, device.memory_image, image_bytes);
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	environment = (struct ntfs_environment){NTFS_API_VERSION, &device,
	    device.image.environment.size_bytes, read_device, allocate, release};
	ntfs_default_limits(&limits);
	limits.record_cache_entries = options.cache_entries;
	result = ntfs_mount(&environment, &limits, &shared.volume);
	if (result == NTFS_OK) {
		result = ntfs_tool_resolve(shared.volume, argv[2], &shared.node);
	}
	if (result == NTFS_OK && options.profile == LOOKUP) {
		result = ntfs_tool_parent(
		    shared.volume, argv[2], &shared.parent, shared.name, &shared.name_units);
	}
	if (result == NTFS_OK) {
		result = ntfs_utf8_to_utf16(options.stream_name, strlen(options.stream_name),
		    shared.stream_name, NTFS_NAME_MAX, &shared.stream_units);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	shared.options = options;
	workers = calloc(options.readers, sizeof(*workers));
	threads = calloc(options.readers, sizeof(*threads));
	samples = calloc(options.operations, sizeof(*samples));
	if (workers == NULL || threads == NULL || samples == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	if (pthread_mutex_init(&shared.core_lock, NULL) != 0) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	core_lock_initialized = true;
	if (pthread_mutex_init(&shared.start_lock, NULL) != 0) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	start_lock_initialized = true;
	if (pthread_cond_init(&shared.start_condition, NULL) != 0) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	condition_initialized = true;
	for (i = 0; i < options.readers; i++) {
		workers[i].shared = &shared;
		workers[i].operations = options.operations / options.readers +
		    (i < options.operations % options.readers);
		workers[i].random = RANDOM_SEED + (uint32_t)i;
		workers[i].samples = samples + sample_offset;
		sample_offset += workers[i].operations;
		if (options.profile == READ_RANDOM || options.profile == READ_SEQUENTIAL ||
		    options.profile == READ_STRIDED) {
			workers[i].buffer = malloc(options.request);
			if (workers[i].buffer == NULL) {
				result = NTFS_NO_MEMORY;
				goto finish;
			}
			result = ntfs_stream_open(shared.node, shared.stream_name,
			    shared.stream_units, &workers[i].stream);
			if (result == NTFS_OK && options.profile == READ_STRIDED &&
			    (ntfs_stream_size(workers[i].stream) == 0 ||
				options.positions - 1 >
				    (ntfs_stream_size(workers[i].stream) - 1) / options.stride)) {
				/* Prove every start fits before multiplying a wide stride.
				 * The last request may still have a truthful partial EOF. */
				result = NTFS_INVALID;
			}
		} else if (options.profile == DIRECTORY_NEXT) {
			result = ntfs_directory_open(shared.node, &workers[i].directory);
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		/* Warmup uses the same live stream/cursor. Measurement continues from
		 * that state; it neither flushes the host page cache nor rewinds data. */
		warmup = options.warmup_operations / options.readers +
		    (i < options.warmup_operations % options.readers);
		for (j = 0; j < warmup; j++) {
			result = one_operation(&workers[i], &count);
			if (result != NTFS_OK) {
				goto finish;
			}
		}
		workers[i].bytes = 0;
		workers[i].entries = 0;
		workers[i].sampled_sum = 0;
	}
	ntfs_get_io_statistics(shared.volume, &before);
	allocations = device.allocations;
	device.peak_bytes = device.live_bytes;
	for (i = 0; i < options.readers; i++) {
		error = pthread_create(&threads[i], NULL, run_worker, &workers[i]);
		if (error != 0) {
			result = NTFS_NO_MEMORY;
			break;
		}
		created++;
	}
	cpu_start = now(CLOCK_PROCESS_CPUTIME_ID);
	start = now(WORKLOAD_WALL_CLOCK);
	pthread_mutex_lock(&shared.start_lock);
	shared.started = true;
	pthread_cond_broadcast(&shared.start_condition);
	pthread_mutex_unlock(&shared.start_lock);
	for (i = 0; i < created; i++) {
		pthread_join(threads[i], NULL);
		if (workers[i].result != NTFS_OK) {
			result = workers[i].result;
		}
		bytes += workers[i].bytes;
		entries += workers[i].entries;
		sum += workers[i].sampled_sum;
	}
	created = 0;
	elapsed = now(WORKLOAD_WALL_CLOCK) - start;
	cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
	if (result != NTFS_OK) {
		goto finish;
	}
	ntfs_get_io_statistics(shared.volume, &after);
	qsort(samples, options.operations, sizeof(*samples), compare_u64);
	if (getrusage(RUSAGE_SELF, &usage) != 0 ||
	    clock_getres(WORKLOAD_WALL_CLOCK, &resolution) != 0) {
		result = NTFS_IO;
		goto finish;
	}
	measured = true;
finish:
	/* No worker exists after the join barrier. Children close before the owner.
	 * Publish a successful measurement only after validating complete teardown. */
	if (created != 0) {
		abort();
	}
	if (workers != NULL) {
		for (i = 0; i < options.readers; i++) {
			ntfs_directory_close(workers[i].directory);
			ntfs_stream_close(workers[i].stream);
			free(workers[i].buffer);
		}
	}
	if (condition_initialized) {
		pthread_cond_destroy(&shared.start_condition);
	}
	if (start_lock_initialized) {
		pthread_mutex_destroy(&shared.start_lock);
	}
	if (core_lock_initialized) {
		pthread_mutex_destroy(&shared.core_lock);
	}
	free(threads);
	free(workers);
	ntfs_node_close(shared.parent);
	ntfs_node_close(shared.node);
	if ((shared.volume != NULL && ntfs_unmount(shared.volume) != NTFS_OK) ||
	    device.live_bytes != 0) {
		result = NTFS_BUSY;
	}
	free(device.memory_image);
	ntfs_image_close(&device.image);
	if (result != NTFS_OK || !measured) {
		free(samples);
		fprintf(stderr, "%s\n", ntfs_result_string(result));
		return 1;
	}
	printf("{\"profile\":\"%s\",\"backend\":\"%s\",\"cache_policy\":\"fresh mount, warmed "
	       "setup, continued stream/cursor after explicit warmup, OS page cache uncontrolled\","
	       "\"concurrency\":\"shared volume with external "
	       "serialization\",\"readers\":%zu,\"operations\":%zu,"
	       "\"warmup_operations\":%zu,"
	       "\"stride_bytes\":%zu,\"positions\":%zu,"
	       "\"wall_clock\":\"" WORKLOAD_WALL_CLOCK_NAME
	       "\",\"wall_clock_resolution_ns\":%" PRIu64 ","
	       "\"request_bytes\":%zu,\"record_cache_entries\":%u,\"wall_ns\":%" PRIu64
	       ",\"cpu_ns\":%" PRIu64 ",\"p50_ns\":%" PRIu64 ",\"p95_ns\":%" PRIu64
	       ",\"p99_ns\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"entries\":%" PRIu64
	       ",\"sampled_sum\":\"%016" PRIx64 "\",\"read_calls\":%" PRIu64
	       ",\"read_bytes\":%" PRIu64 ",\"record_cache_hits\":%" PRIu64
	       ",\"record_cache_misses\":%" PRIu64 ",\"allocations\":%" PRIu64
	       ",\"peak_core_bytes\":%zu,\"peak_rss_bytes\":%" PRIu64 "}\n",
	    options.profile_name, options.memory_backend ? "memory" : "posix", options.readers,
	    options.operations, options.warmup_operations, options.stride, options.positions,
	    (uint64_t)resolution.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)resolution.tv_nsec,
	    options.request, options.cache_entries, elapsed, cpu,
	    percentile(samples, options.operations, PERCENTILE_MEDIAN),
	    percentile(samples, options.operations, PERCENTILE_TAIL),
	    percentile(samples, options.operations, PERCENTILE_EXTREME), bytes, entries, sum,
	    after.read_calls - before.read_calls, after.read_bytes - before.read_bytes,
	    after.record_cache_hits - before.record_cache_hits,
	    after.record_cache_misses - before.record_cache_misses,
	    device.allocations - allocations, device.peak_bytes,
#ifdef __APPLE__
	    (uint64_t)usage.ru_maxrss
#else
	    (uint64_t)usage.ru_maxrss * KIBIBYTE_BYTES
#endif
	);
	free(samples);
	return 0;
}
