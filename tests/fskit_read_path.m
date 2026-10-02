/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#import "fskit_read_path.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_SOURCE_BYTES = 4 * NTFS_RESOURCE_WINDOW,
	TEST_COMMON_ALIGNMENT = 4096,
	TEST_GUARD_BYTE = 0xa5,
	TEST_PATTERN_FACTOR = 29,
	TEST_PATTERN_PERIOD = 251,
	TEST_TRACE_CAPACITY = 4,
	TEST_PARTIAL_DIVISOR = 2
};

enum read_fault {
	READ_FULL,
	READ_SHORT,
	READ_PARTIAL_ERROR,
	READ_FULL_ERROR,
	READ_ZERO_ERROR,
	READ_OVER_REPORTED,
	READ_REVOKED,
	READ_FAULT_END
};

struct read_trace {
	uint64_t offset;
	size_t length, copied;
	bool direct;
};

@interface ReadPathReader : NSObject <NTFSBlockReader> {
      @public
	struct read_trace trace[TEST_TRACE_CAPACITY];
}
@property const uint8_t *source;
@property uint8_t *caller;
@property size_t callerLength;
@property size_t alignment;
@property size_t calls;
@property size_t faultCall;
@property enum read_fault fault;
@property(getter=isRevoked) BOOL revoked;
@end

@implementation ReadPathReader

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
	return TEST_SOURCE_BYTES / self.blockSize;
}

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	struct read_trace *entry;
	uintptr_t address = (uintptr_t)buffer, caller = (uintptr_t)self.caller;
	size_t copied = length, reported = length;
	enum read_fault fault;

	assert(self.calls < TEST_TRACE_CAPACITY);
	assert(offset >= 0 && (uint64_t)offset % self.alignment == 0);
	assert((uint64_t)offset <= TEST_SOURCE_BYTES &&
	    length <= TEST_SOURCE_BYTES - (uint64_t)offset);
	assert(length != 0 && length <= NTFS_RESOURCE_WINDOW && length % self.alignment == 0);
	assert(address % self.alignment == 0 && *error == nil);
	entry = &trace[self.calls++];
	entry->offset = (uint64_t)offset;
	entry->length = length;
	entry->direct = address >= caller && address - caller <= self.callerLength &&
	    length <= self.callerLength - (address - caller);
	fault = self.calls == self.faultCall ? self.fault : READ_FULL;
	if (fault == READ_SHORT) {
		copied = reported = length - 1;
	} else if (fault == READ_PARTIAL_ERROR) {
		copied = reported = length / TEST_PARTIAL_DIVISOR;
	} else if (fault == READ_ZERO_ERROR) {
		copied = reported = 0;
	} else if (fault == READ_OVER_REPORTED) {
		reported = length + 1;
	} else if (fault == READ_REVOKED) {
		self.revoked = YES;
	}
	if (fault == READ_PARTIAL_ERROR || fault == READ_FULL_ERROR || fault == READ_ZERO_ERROR) {
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
	}
	memcpy(buffer, self.source + (size_t)offset, copied);
	entry->copied = copied;
	return reported;
}

@end

@interface ReadPathResource : NTFSResource
@property size_t allocations;
@end

@implementation ReadPathResource

- (void *)allocateSize:(size_t)size
{
	self.allocations++;
	return [super allocateSize:size];
}

@end

struct read_case {
	uint64_t offset;
	size_t length, pointerShift, calls, directCalls, deviceBytes;
};

static void
check_poison(const uint8_t *bytes, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++) {
		assert(bytes[i] == TEST_GUARD_BYTE);
	}
}

static void
check_guards(const uint8_t *allocation, size_t leading, size_t length, size_t trailing)
{
	check_poison(allocation, leading);
	check_poison(allocation + leading + length, trailing);
}

static void
test_geometry(const uint8_t *source, uint8_t *allocation, size_t alignment, size_t *verdicts)
{
	const struct read_case cases[] = {{alignment, alignment, 0, 1, 1, alignment},
	    {alignment, NTFS_RESOURCE_WINDOW, 0, 1, 1, NTFS_RESOURCE_WINDOW},
	    {alignment, NTFS_RESOURCE_WINDOW + alignment, 0, 2, 2,
		NTFS_RESOURCE_WINDOW + alignment},
	    {alignment + 1, alignment, 0, 1, 0, 2 * alignment},
	    {alignment, alignment, 1, 1, 0, alignment},
	    {alignment, alignment - 1, 0, 1, 0, alignment},
	    {alignment, NTFS_RESOURCE_WINDOW + 1, 0, 2, 1, NTFS_RESOURCE_WINDOW + alignment},
	    {alignment, NTFS_RESOURCE_WINDOW + alignment, 1, 2, 0,
		NTFS_RESOURCE_WINDOW + alignment},
	    {alignment + 1, 2 * NTFS_RESOURCE_WINDOW, 0, 3, 0,
		2 * NTFS_RESOURCE_WINDOW + alignment},
	    {TEST_SOURCE_BYTES - alignment, alignment, 0, 1, 1, alignment},
	    {TEST_SOURCE_BYTES - alignment + 1, alignment - 1, 0, 1, 0, alignment}};
	ReadPathReader *reader = [[ReadPathReader alloc] init];
	ReadPathResource *resource;
	uint8_t *buffer;
	size_t i, j, leading, directCalls, deviceBytes;
	struct ntfs_environment environment;

	reader.source = source;
	reader.alignment = alignment;
	resource = [[ReadPathResource alloc] initWithReader:reader];
	assert(resource != nil);
	environment = [resource environment];
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		leading = alignment + cases[i].pointerShift;
		buffer = allocation + leading;
		memset(allocation, TEST_GUARD_BYTE, leading + cases[i].length + alignment);
		reader.caller = buffer;
		reader.callerLength = cases[i].length;
		reader.calls = 0;
		assert(environment.read(environment.context, cases[i].offset, buffer,
			   cases[i].length) == NTFS_OK);
		assert(memcmp(buffer, source + cases[i].offset, cases[i].length) == 0);
		check_guards(allocation, leading, cases[i].length, alignment);
		directCalls = deviceBytes = 0;
		for (j = 0; j < reader.calls; j++) {
			directCalls += reader->trace[j].direct;
			deviceBytes += reader->trace[j].length;
		}
		assert(reader.calls == cases[i].calls && directCalls == cases[i].directCalls &&
		    deviceBytes == cases[i].deviceBytes && resource.allocations == 0);
		(*verdicts)++;
	}
	reader.calls = 0;
	assert([resource readAt:TEST_SOURCE_BYTES bytes:NULL length:0] == NTFS_OK);
	assert([resource readAt:TEST_SOURCE_BYTES + 1 bytes:NULL length:0] == NTFS_IO);
	assert([resource readAt:TEST_SOURCE_BYTES bytes:allocation length:1] == NTFS_IO);
	assert([resource readAt:UINT64_MAX bytes:allocation length:alignment] == NTFS_IO);
	assert([resource readAt:0 bytes:NULL length:1] == NTFS_IO);
	assert(reader.calls == 0 && resource.allocations == 0);
	*verdicts += 5;
}

static void
test_faults(const uint8_t *source, uint8_t *allocation, size_t alignment, size_t *verdicts)
{
	enum read_fault fault;
	size_t position, pointerShift, leading, length = NTFS_RESOURCE_WINDOW + alignment;
	size_t prefix, j, directCalls;
	uint8_t *buffer;
	ReadPathReader *reader;
	ReadPathResource *resource;

	for (fault = READ_SHORT; fault < READ_FAULT_END; fault++) {
		for (pointerShift = 0; pointerShift <= 1; pointerShift++) {
			for (position = 1; position <= 2; position++) {
				reader = [[ReadPathReader alloc] init];
				reader.source = source;
				reader.alignment = alignment;
				reader.fault = fault;
				reader.faultCall = position;
				leading = alignment + pointerShift;
				buffer = allocation + leading;
				reader.caller = buffer;
				reader.callerLength = length;
				resource = [[ReadPathResource alloc] initWithReader:reader];
				assert(resource != nil);
				memset(allocation, TEST_GUARD_BYTE, leading + length + alignment);
				assert([resource readAt:alignment bytes:buffer
						 length:length] == NTFS_IO);
				assert(reader.calls == position && resource.allocations == 0);
				directCalls = 0;
				for (j = 0; j < reader.calls; j++) {
					directCalls += reader->trace[j].direct;
				}
				assert(directCalls == (pointerShift == 0 ? position : 0));
				/* Earlier exact fragments may be visible on failure. A direct
				 * failed transfer may also expose its partial/full device fill. */
				prefix = position == 2 ? NTFS_RESOURCE_WINDOW : 0;
				if (pointerShift == 0) {
					prefix += reader->trace[position - 1].copied;
				}
				assert(memcmp(buffer, source + alignment, prefix) == 0);
				check_poison(buffer + prefix, length - prefix);
				check_guards(allocation, leading, length, alignment);
				reader.faultCall = 0;
				reader.revoked = NO;
				reader.calls = 0;
				if (fault == READ_REVOKED) {
					assert(!resource.isAvailable);
					assert([resource readAt:alignment
							  bytes:buffer
							 length:length] == NTFS_IO);
					assert([resource readAt:0 bytes:NULL length:0] == NTFS_IO);
					assert(reader.calls == 0);
				} else {
					assert([resource readAt:alignment
							  bytes:buffer
							 length:length] == NTFS_OK);
					assert(reader.calls == 2 &&
					    memcmp(buffer, source + alignment, length) == 0);
					check_guards(allocation, leading, length, alignment);
				}
				assert(resource.allocations == 0);
				(*verdicts)++;
			}
		}
	}
}

void
ntfs_test_fskit_read_path(void)
{
	const size_t alignments[] = {
	    NTFS_RESOURCE_MIN_ALIGNMENT, TEST_COMMON_ALIGNMENT, NTFS_RESOURCE_MAX_ALIGNMENT};
	uint8_t *source = NULL, *allocation = NULL;
	size_t i, j,
	    verdicts = 0,
	    allocationBytes = 2 * NTFS_RESOURCE_WINDOW + 3 * NTFS_RESOURCE_MAX_ALIGNMENT + 1;

	assert(
	    posix_memalign((void **)&source, NTFS_RESOURCE_MAX_ALIGNMENT, TEST_SOURCE_BYTES) == 0);
	assert(posix_memalign((void **)&allocation, NTFS_RESOURCE_MAX_ALIGNMENT, allocationBytes) ==
	    0);
	for (i = 0; i < TEST_SOURCE_BYTES; i++) {
		source[i] = (uint8_t)(i * TEST_PATTERN_FACTOR % TEST_PATTERN_PERIOD);
	}
	for (i = 0; i < sizeof(alignments) / sizeof(alignments[0]); i++) {
		test_geometry(source, allocation, alignments[i], &verdicts);
		test_faults(source, allocation, alignments[i], &verdicts);
	}
	for (j = 0; j < TEST_SOURCE_BYTES; j++) {
		assert(source[j] == (uint8_t)(j * TEST_PATTERN_FACTOR % TEST_PATTERN_PERIOD));
	}
	free(allocation);
	free(source);
	printf(
	    "PASS: FSKit direct/window reads, %zu geometry/fault verdicts at three physical "
	    "alignments, exact bytes/guards, no core allocations, retry and permanent revocation\n",
	    verdicts);
}
