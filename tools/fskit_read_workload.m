/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

enum {
	WORKLOAD_SOURCE_BYTES = 64 * NTFS_RESOURCE_WINDOW,
	WORKLOAD_MAX_OPERATIONS = 1000000,
	WORKLOAD_GUARD_BYTE = 0xa5,
	WORKLOAD_PATTERN_FACTOR = 29,
	WORKLOAD_PATTERN_PERIOD = 251,
	WORKLOAD_PATTERN_BLOCK_FACTOR = 7,
	DECIMAL_RADIX = 10,
	PERCENTILE_DENOMINATOR = 100,
	PERCENTILE_MEDIAN = 50,
	PERCENTILE_TAIL = 95,
	PERCENTILE_EXTREME = 99,
	HEX_DIGITS_PER_BYTE = 2
};

#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)

/* Every callback is checked against the same physical transfer requirements.
 * Caller destinations identify direct transfers without product instrumentation. */
@interface WorkloadReader : NSObject <NTFSBlockReader>
@property const uint8_t *source;
@property size_t alignment;
@property uint8_t *caller;
@property size_t callerLength;
@property uint64_t calls;
@property uint64_t bytes;
@property uint64_t directCalls;
@property uint64_t directBytes;
@property BOOL invalidTransfer;
@end

@implementation WorkloadReader

- (uint64_t)blockSize
{
	return NTFS_RESOURCE_MIN_ALIGNMENT;
}

- (uint64_t)physicalBlockSize
{
	return self.alignment;
}

- (uint64_t)blockCount
{
	return WORKLOAD_SOURCE_BYTES / self.blockSize;
}

- (BOOL)isRevoked
{
	return NO;
}

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	uintptr_t address = (uintptr_t)buffer, caller = (uintptr_t)self.caller;

	if (offset < 0 || (uint64_t)offset > WORKLOAD_SOURCE_BYTES ||
	    length > WORKLOAD_SOURCE_BYTES - (uint64_t)offset ||
	    (uint64_t)offset % self.alignment != 0 || length % self.alignment != 0 ||
	    address % self.alignment != 0 || length == 0 || length > NTFS_RESOURCE_WINDOW) {
		self.invalidTransfer = YES;
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return 0;
	}
	self.calls++;
	self.bytes += length;
	if (address >= caller && address - caller <= self.callerLength &&
	    length <= self.callerLength - (address - caller)) {
		self.directCalls++;
		self.directBytes += length;
	}
	memcpy(buffer, self.source + (size_t)offset, length);
	return length;
}

@end

static uint64_t
now(clockid_t clock)
{
	struct timespec value;

	if (clock_gettime(clock, &value) != 0) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)value.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)value.tv_nsec;
}

static bool
parse_decimal(const char *text, size_t maximum, size_t *out)
{
	size_t value = 0, digit;

	if (*text == '\0') {
		return false;
	}
	while (*text != '\0') {
		if (*text < '0' || *text > '9') {
			return false;
		}
		digit = (size_t)(*text++ - '0');
		if (value > maximum / DECIMAL_RADIX ||
		    (value == maximum / DECIMAL_RADIX && digit > maximum % DECIMAL_RADIX)) {
			return false;
		}
		value = value * DECIMAL_RADIX + digit;
	}
	*out = value;
	return true;
}

static NSString *
source_digest(const uint8_t *source)
{
	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	char hex[sizeof(digest) * HEX_DIGITS_PER_BYTE + 1];
	size_t i;

	CC_SHA256(source, WORKLOAD_SOURCE_BYTES, digest);
	for (i = 0; i < sizeof(digest); i++) {
		snprintf(hex + i * HEX_DIGITS_PER_BYTE, HEX_DIGITS_PER_BYTE + 1, "%02x", digest[i]);
	}
	return @(hex);
}

static bool
guards(const uint8_t *allocation, size_t leading, size_t length, size_t trailing)
{
	size_t i;

	for (i = 0; i < leading; i++) {
		if (allocation[i] != WORKLOAD_GUARD_BYTE) {
			return false;
		}
	}
	for (i = leading + length; i < leading + length + trailing; i++) {
		if (allocation[i] != WORKLOAD_GUARD_BYTE) {
			return false;
		}
	}
	return true;
}

static int
compare_sample(const void *a, const void *b)
{
	uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;

	return left < right ? -1 : left > right;
}

static uint64_t
percentile(const uint64_t *samples, size_t count, size_t percent)
{
	size_t rank = (count * percent + PERCENTILE_DENOMINATOR - 1) / PERCENTILE_DENOMINATOR;

	return samples[rank - 1];
}

static enum ntfs_result
read_request(NTFSResource *resource, WorkloadReader *reader, bool direct, uint64_t offset,
    uint8_t *buffer, size_t length)
{
	size_t take, completed;
	NSError *error;

	if (!direct) {
		return [resource readAt:offset bytes:buffer length:length];
	}
	while (length != 0) {
		take = MIN(length, NTFS_RESOURCE_WINDOW);
		error = nil;
		completed = [reader readInto:buffer
				  startingAt:(off_t)offset
				      length:take
				       error:&error];
		if (error != nil || completed != take) {
			return NTFS_IO;
		}
		buffer += take;
		offset += take;
		length -= take;
	}
	return NTFS_OK;
}

int
main(int argc, char **argv)
{
	@autoreleasepool {
		size_t request, alignment, operations, warmup, length, leading, total, slots, i;
		size_t offsetShift = 0, pointerShift = 0;
		uint8_t *source = NULL, *allocation = NULL, *buffer;
		uint64_t *samples = NULL, offset, start, wall, cpu, sampledSum = 0;
		bool direct, alignedProfile, multiProfile;
		WorkloadReader *reader;
		NTFSResource *resource;
		NSString *before, *after;
		struct rusage usage;
		NSDictionary *report;
		NSData *json;
		int status = 1;

		if (argc != 7 || !parse_decimal(argv[3], NTFS_RESOURCE_WINDOW, &request) ||
		    !parse_decimal(argv[4], NTFS_RESOURCE_MAX_ALIGNMENT, &alignment) ||
		    !parse_decimal(argv[5], WORKLOAD_MAX_OPERATIONS, &operations) ||
		    !parse_decimal(argv[6], WORKLOAD_MAX_OPERATIONS, &warmup) || operations == 0 ||
		    alignment < NTFS_RESOURCE_MIN_ALIGNMENT || (alignment & (alignment - 1)) != 0 ||
		    request < alignment || request % alignment != 0) {
			fprintf(stderr,
			    "usage: %s PROFILE resource|reader REQUEST ALIGNMENT OPERATIONS "
			    "WARMUP\n",
			    argv[0]);
			return 2;
		}
		direct = strcmp(argv[2], "reader") == 0;
		alignedProfile = strcmp(argv[1], "aligned") == 0;
		multiProfile = strcmp(argv[1], "multi-window") == 0;
		length = request;
		if (strcmp(argv[1], "offset") == 0) {
			offsetShift = 1;
		} else if (strcmp(argv[1], "pointer") == 0) {
			pointerShift = 1;
		} else if (strcmp(argv[1], "length") == 0) {
			length--;
		} else if (multiProfile && request == NTFS_RESOURCE_WINDOW) {
			length += alignment;
		} else if (!alignedProfile) {
			fprintf(stderr, "unknown profile or invalid multi-window request\n");
			return 2;
		}
		if ((!direct && strcmp(argv[2], "resource") != 0) ||
		    (direct && !alignedProfile && !multiProfile)) {
			fprintf(stderr, "reader control requires an aligned profile\n");
			return 2;
		}
		leading = alignment + pointerShift;
		total = leading + length + alignment;
		slots = (WORKLOAD_SOURCE_BYTES - offsetShift - length) / request + 1;
		if (posix_memalign((void **)&source, alignment, WORKLOAD_SOURCE_BYTES) != 0 ||
		    posix_memalign((void **)&allocation, alignment, total) != 0 ||
		    (samples = malloc(operations * sizeof(*samples))) == NULL) {
			fprintf(stderr, "workload allocation failed\n");
			goto cleanup;
		}
		buffer = allocation + leading;
		memset(allocation, WORKLOAD_GUARD_BYTE, total);
		for (i = 0; i < WORKLOAD_SOURCE_BYTES; i++) {
			source[i] = (uint8_t)((i * WORKLOAD_PATTERN_FACTOR +
						  i / NTFS_RESOURCE_MIN_ALIGNMENT *
						      WORKLOAD_PATTERN_BLOCK_FACTOR) %
			    WORKLOAD_PATTERN_PERIOD);
		}
		before = source_digest(source);
		reader = [[WorkloadReader alloc] init];
		reader.source = source;
		reader.alignment = alignment;
		reader.caller = buffer;
		reader.callerLength = length;
		resource = [[NTFSResource alloc] initWithReader:reader];
		if (resource == nil) {
			fprintf(stderr, "resource acquisition failed\n");
			goto cleanup;
		}
		/* Full byte/guard oracles precede and follow the measured phase. Interior
		 * per-request samples detect data changes without scanning each large read. */
		if (read_request(resource, reader, direct, offsetShift, buffer, length) !=
			NTFS_OK ||
		    memcmp(buffer, source + offsetShift, length) != 0 ||
		    !guards(allocation, leading, length, alignment)) {
			fprintf(stderr, "initial byte/guard oracle failed\n");
			goto cleanup;
		}
		for (i = 0; i < warmup; i++) {
			offset = (uint64_t)(i % slots) * request + offsetShift;
			if (read_request(resource, reader, direct, offset, buffer, length) !=
			    NTFS_OK) {
				fprintf(stderr, "warmup read failed\n");
				goto cleanup;
			}
		}
		reader.calls = reader.bytes = reader.directCalls = reader.directBytes = 0;
		cpu = now(CLOCK_PROCESS_CPUTIME_ID);
		wall = now(CLOCK_MONOTONIC_RAW);
		for (i = 0; i < operations; i++) {
			offset = (uint64_t)(i % slots) * request + offsetShift;
			start = now(CLOCK_MONOTONIC_RAW);
			if (read_request(resource, reader, direct, offset, buffer, length) !=
			    NTFS_OK) {
				fprintf(stderr, "measured read failed\n");
				goto cleanup;
			}
			samples[i] = now(CLOCK_MONOTONIC_RAW) - start;
			if (buffer[0] != source[offset] ||
			    buffer[length / 2] != source[offset + length / 2] ||
			    buffer[length - 1] != source[offset + length - 1]) {
				fprintf(stderr, "per-request byte oracle failed\n");
				goto cleanup;
			}
			sampledSum += buffer[0] + buffer[length / 2] + buffer[length - 1];
		}
		wall = now(CLOCK_MONOTONIC_RAW) - wall;
		cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
		offset = (uint64_t)((operations - 1) % slots) * request + offsetShift;
		after = source_digest(source);
		if (reader.invalidTransfer || reader.directBytes > (uint64_t)operations * length ||
		    memcmp(buffer, source + offset, length) != 0 ||
		    ![before isEqualToString:after] ||
		    !guards(allocation, leading, length, alignment) ||
		    getrusage(RUSAGE_SELF, &usage) != 0) {
			fprintf(stderr, "final byte/guard/immutable-source oracle failed\n");
			goto cleanup;
		}
		qsort(samples, operations, sizeof(*samples), compare_sample);
		report = @{
			@"schema" : @1,
			@"profile" : @(argv[1]),
			@"backend" : @(argv[2]),
			@"scope" :
			    @"real FSKit resource, synchronous memory reader; no native device",
			@"request_bytes" : @(request),
			@"operation_bytes" : @(length),
			@"alignment" : @(alignment),
			@"operations" : @(operations),
			@"warmup_operations" : @(warmup),
			@"source_bytes" : @(WORKLOAD_SOURCE_BYTES),
			@"source_sha256_before" : before,
			@"source_sha256_after" : after,
			@"bytes" : @((uint64_t)operations * length),
			@"wall_ns" : @(wall),
			@"cpu_ns" : @(cpu),
			@"p50_ns" : @(percentile(samples, operations, PERCENTILE_MEDIAN)),
			@"p95_ns" : @(percentile(samples, operations, PERCENTILE_TAIL)),
			@"p99_ns" : @(percentile(samples, operations, PERCENTILE_EXTREME)),
			@"read_calls" : @(reader.calls),
			@"read_bytes" : @(reader.bytes),
			@"direct_read_calls" : @(reader.directCalls),
			@"direct_read_bytes" : @(reader.directBytes),
			@"window_read_calls" : @(reader.calls - reader.directCalls),
			@"window_read_bytes" : @(reader.bytes - reader.directBytes),
			@"inferred_bounce_copy_bytes" :
			    @((uint64_t)operations * length - reader.directBytes),
			@"resource_window_bytes" : @(NTFS_RESOURCE_WINDOW),
			@"core_allocations" : @0,
			@"core_peak_bytes" : @0,
			@"peak_rss_bytes" : @(usage.ru_maxrss),
			@"sampled_sum" : @(sampledSum),
			@"byte_oracles" :
			    @"full first/last requests, three samples per measured request",
			@"guards" : @"pass",
			@"source_immutable" : @YES
		};
		json = [NSJSONSerialization dataWithJSONObject:report options:0 error:nil];
		if (json == nil || fwrite(json.bytes, 1, json.length, stdout) != json.length ||
		    putchar('\n') == EOF) {
			fprintf(stderr, "report output failed\n");
			goto cleanup;
		}
		status = 0;
	cleanup:
		free(samples);
		free(allocation);
		free(source);
		return status;
	}
}
