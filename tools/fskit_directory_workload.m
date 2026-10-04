/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
	WORKLOAD_MAX_IMAGE_BYTES = 64 * NTFS_RESOURCE_WINDOW,
	WORKLOAD_MAX_MANIFEST_BYTES = 16 * NTFS_RESOURCE_WINDOW,
	WORKLOAD_MAX_ENTRIES = 16384,
	WORKLOAD_MAX_PAGE_ENTRIES = 1024,
	WORKLOAD_MAX_ROUNDS = 100,
	WORKLOAD_MAX_SAMPLES = 1000000,
	WORKLOAD_MAX_RECORD_CACHE_ENTRIES = NTFS_DEFAULT_RECORD_CACHE_ENTRIES,
	WORKLOAD_READERS = 2,
	WORKLOAD_VIRTUAL_ENTRIES = 2,
	WORKLOAD_CURRENT_ENTRY = 0,
	WORKLOAD_DECIMAL_RADIX = 10,
	PERCENTILE_DENOMINATOR = 100,
	PERCENTILE_MEDIAN = 50,
	PERCENTILE_TAIL = 95,
	PERCENTILE_EXTREME = 99,
	ARG_IMAGE = 1,
	ARG_MANIFEST,
	ARG_PROFILE,
	ARG_FIRST_PAGE,
	ARG_SECOND_PAGE,
	ARG_ROUNDS,
	ARG_WARMUP,
	ARG_RECORD_CACHE,
	ARG_COUNT
};

#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)

@interface DirectoryReader : NSObject <NTFSBlockReader>
@property NSData *image;
@property uint64_t calls;
@property uint64_t bytes;
@end

@implementation DirectoryReader

- (uint64_t)blockSize
{
	return NTFS_RESOURCE_MIN_ALIGNMENT;
}

- (uint64_t)physicalBlockSize
{
	return self.blockSize;
}

- (uint64_t)blockCount
{
	return self.image.length / self.blockSize;
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
	(void)error;
	assert(offset >= 0 && (uint64_t)offset <= self.image.length &&
	    length <= self.image.length - (size_t)offset);
	assert((uint64_t)offset % self.blockSize == 0 && length % self.blockSize == 0 &&
	    (uintptr_t)buffer % self.blockSize == 0);
	self.calls++;
	self.bytes += length;
	memcpy(buffer, (const uint8_t *)self.image.bytes + (size_t)offset, length);
	return length;
}

@end

@interface DirectoryResource : NTFSResource
@property uint64_t allocations;
@property uint64_t liveBytes;
@property uint64_t peakBytes;
@end

@implementation DirectoryResource

- (void *)allocateSize:(size_t)size
{
	void *bytes = [super allocateSize:size];

	self.allocations++;
	if (bytes != NULL) {
		self.liveBytes += size;
		self.peakBytes = MAX(self.peakBytes, self.liveBytes);
	}
	return bytes;
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	if (bytes != NULL) {
		assert(self.liveBytes >= size);
		self.liveBytes -= size;
	}
	[super releaseBytes:bytes size:size];
}

@end

/* Expected names, identities and sizes come from the independent fixture author,
 * never from a first run of the product being measured. */
@interface DirectoryPacker : NSObject
@property NSArray<NSDictionary *> *expected;
@property NSUInteger position;
@property NSUInteger accepted;
@property NSUInteger capacity;
@property BOOL attributes;
@property FSDirectoryCookie cookie;
@end

@implementation DirectoryPacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	NSDictionary *entry;
	NSUInteger index = self.position + self.accepted;
	BOOL virtualEntry;

	if (self.accepted == self.capacity) {
		return NO;
	}
	virtualEntry = !self.attributes && index < WORKLOAD_VIRTUAL_ENTRIES;
	if (virtualEntry) {
		assert(
		    [name.string isEqualToString:index == WORKLOAD_CURRENT_ENTRY ? @"." : @".."]);
		assert(type == FSItemTypeDirectory && itemID == FSItemIDRootDirectory);
	} else {
		index -= self.attributes ? 0 : WORKLOAD_VIRTUAL_ENTRIES;
		assert(index < self.expected.count);
		entry = self.expected[index];
		assert([name.string isEqualToString:entry[@"native"]]);
		assert(itemID == [entry[@"reference"] unsignedLongLongValue] &&
		    type == FSItemTypeFile);
		if (self.attributes) {
			assert(attributes != nil && attributes.fileID == itemID &&
			    attributes.type == type &&
			    attributes.size == [entry[@"size"] unsignedLongLongValue]);
		}
	}
	assert(self.attributes || attributes == nil);
	assert(cookie != FSDirectoryCookieInitial);
	self.cookie = cookie;
	self.accepted++;
	return YES;
}

@end

static uint64_t
now(clockid_t clock)
{
	struct timespec value;

	assert(clock_gettime(clock, &value) == 0);
	return (uint64_t)value.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)value.tv_nsec;
}

static NSData *
bounded_data(const char *path, size_t maximum)
{
	struct stat info;
	uint8_t *bytes = NULL;
	NSData *result = nil;
	size_t position = 0, length;
	ssize_t completed;
	int descriptor;

	descriptor = open(path, O_RDONLY | O_NONBLOCK);
	if (descriptor < 0) {
		return nil;
	}
	if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
	    (uint64_t)info.st_size > maximum) {
		goto finish;
	}
	length = (size_t)info.st_size;
	bytes = malloc(length);
	if (bytes == NULL) {
		goto finish;
	}
	while (position < length) {
		completed = read(descriptor, bytes + position, length - position);
		if (completed < 0 && errno == EINTR) {
			continue;
		}
		if (completed <= 0) {
			goto finish;
		}
		position += (size_t)completed;
	}
	result = [[NSData alloc] initWithBytesNoCopy:bytes length:length freeWhenDone:YES];
	if (result != nil) {
		bytes = NULL;
	}
finish:
	free(bytes);
	close(descriptor);
	return result;
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
		if (value > (maximum - digit) / WORKLOAD_DECIMAL_RADIX) {
			return false;
		}
		value = value * WORKLOAD_DECIMAL_RADIX + digit;
	}
	*out = value;
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

static void
round_scan(NTFSLegacyVolume *volume, FSItem *root, NSArray *expected, NSString *profile,
    const size_t *pages, uint64_t *samples, size_t capacity, size_t *count, uint64_t *entries)
{
	DirectoryPacker *packers[WORKLOAD_READERS];
	FSItemGetAttributesRequest *request = [[FSItemGetAttributesRequest alloc] init];
	BOOL finished[WORKLOAD_READERS] = {NO, NO};
	size_t readers = [profile isEqualToString:@"sequential"] ? 1 : WORKLOAD_READERS;
	size_t reader, remaining = readers;
	uint64_t start;
	NSUInteger total, replies;

	request.wantedAttributes =
	    FSItemAttributeType | FSItemAttributeFileID | FSItemAttributeSize;
	for (reader = 0; reader < readers; reader++) {
		packers[reader] = [[DirectoryPacker alloc] init];
		packers[reader].expected = expected;
		packers[reader].capacity = pages[reader];
		packers[reader].attributes = ![profile isEqualToString:@"views"] || reader != 0;
	}
	while (remaining != 0) {
		for (reader = 0; reader < readers; reader++) {
			if (finished[reader]) {
				continue;
			}
			@autoreleasepool {
				DirectoryPacker *packer = packers[reader];
				__block NSError *failure = nil;
				__block NSUInteger completed = 0;

				packer.accepted = 0;
				start = now(CLOCK_MONOTONIC_RAW);
				[volume enumerateDirectory:root
					  startingAtCookie:packer.cookie
						  verifier:packer.cookie == FSDirectoryCookieInitial
					? FSDirectoryVerifierInitial
					: volume.directoryVerifier
				       providingAttributes:packer.attributes ? request : nil
					       usingPacker:(FSDirectoryEntryPacker *)packer
					      replyHandler:^(
						  FSDirectoryVerifier verifier, NSError *error) {
						assert(verifier == volume.directoryVerifier);
						failure = error;
						completed++;
					      }];
				if (samples != NULL) {
					assert(*count < capacity);
					samples[(*count)++] = now(CLOCK_MONOTONIC_RAW) - start;
				}
				replies = completed;
				assert(replies == 1 && failure == nil);
				packer.position += packer.accepted;
				*entries += packer.accepted;
				total = expected.count +
				    (packer.attributes ? 0 : WORKLOAD_VIRTUAL_ENTRIES);
				assert(packer.position <= total);
				if (packer.accepted == 0) {
					assert(packer.position == total);
					finished[reader] = YES;
					remaining--;
				}
			}
		}
	}
}

int
main(int argc, char **argv)
{
	@autoreleasepool {
		NSData *image, *manifest, *output;
		NSArray *expected;
		NSString *profile;
		DirectoryReader *reader;
		DirectoryResource *resource;
		NTFSLegacyVolume *volume;
		struct ntfs_volume *core = NULL;
		struct ntfs_environment environment;
		struct ntfs_limits limits;
		struct rusage usage;
		FSItem *root;
		NSError *error = nil;
		size_t pages[WORKLOAD_READERS], rounds, warmup, round, capacity, count = 0;
		size_t recordCache = 0;
		uint64_t *samples, entries = 0, ignored = 0, start, wall, cpu;
		uint64_t reads, readBytes, allocations, baselineBytes;

		if ((argc != ARG_RECORD_CACHE && argc != ARG_COUNT) ||
		    !parse_decimal(argv[ARG_FIRST_PAGE], WORKLOAD_MAX_PAGE_ENTRIES, &pages[0]) ||
		    !parse_decimal(argv[ARG_SECOND_PAGE], WORKLOAD_MAX_PAGE_ENTRIES, &pages[1]) ||
		    !parse_decimal(argv[ARG_ROUNDS], WORKLOAD_MAX_ROUNDS, &rounds) ||
		    !parse_decimal(argv[ARG_WARMUP], WORKLOAD_MAX_ROUNDS, &warmup) ||
		    (argc == ARG_COUNT &&
			!parse_decimal(argv[ARG_RECORD_CACHE], WORKLOAD_MAX_RECORD_CACHE_ENTRIES,
			    &recordCache)) ||
		    pages[0] == 0 || pages[1] == 0 || rounds == 0) {
			fputs("usage: ntfs-fskit-directory-workload IMAGE MANIFEST "
			      "sequential|interleaved|views PAGE_A PAGE_B ROUNDS WARMUP "
			      "[RECORD_CACHE]\n",
			    stderr);
			return 2;
		}
		profile = @(argv[ARG_PROFILE]);
		assert(([@[ @"sequential", @"interleaved", @"views" ] containsObject:profile]));
		image = bounded_data(argv[ARG_IMAGE], WORKLOAD_MAX_IMAGE_BYTES);
		manifest = bounded_data(argv[ARG_MANIFEST], WORKLOAD_MAX_MANIFEST_BYTES);
		assert(image.length != 0 && image.length <= WORKLOAD_MAX_IMAGE_BYTES &&
		    manifest.length != 0 && manifest.length <= WORKLOAD_MAX_MANIFEST_BYTES);
		expected = [NSJSONSerialization JSONObjectWithData:manifest options:0 error:&error];
		assert(error == nil && [expected isKindOfClass:[NSArray class]] &&
		    expected.count != 0 && expected.count <= WORKLOAD_MAX_ENTRIES);
		capacity =
		    rounds * WORKLOAD_READERS * (expected.count + WORKLOAD_VIRTUAL_ENTRIES + 1);
		assert(capacity <= WORKLOAD_MAX_SAMPLES);
		samples = calloc(capacity, sizeof(*samples));
		assert(samples != NULL);
		reader = [[DirectoryReader alloc] init];
		reader.image = image;
		resource = [[DirectoryResource alloc] initWithReader:reader];
		environment = [resource environment];
		ntfs_default_limits(&limits);
		limits.record_cache_entries = (uint32_t)recordCache;
		assert(ntfs_mount(&environment, &limits, &core) == NTFS_OK);
		volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
		assert(volume != nil);
		root = [volume activateExtraction:&error];
		assert(root != nil && error == nil);
		for (round = 0; round < warmup; round++) {
			round_scan(
			    volume, root, expected, profile, pages, NULL, 0, &count, &ignored);
		}
		reads = reader.calls;
		readBytes = reader.bytes;
		allocations = resource.allocations;
		baselineBytes = resource.liveBytes;
		resource.peakBytes = baselineBytes;
		start = now(CLOCK_PROCESS_CPUTIME_ID);
		wall = now(CLOCK_MONOTONIC_RAW);
		for (round = 0; round < rounds; round++) {
			round_scan(volume, root, expected, profile, pages, samples, capacity,
			    &count, &entries);
		}
		wall = now(CLOCK_MONOTONIC_RAW) - wall;
		cpu = now(CLOCK_PROCESS_CPUTIME_ID) - start;
		assert(count != 0 && getrusage(RUSAGE_SELF, &usage) == 0);
		qsort(samples, count, sizeof(*samples), compare_sample);
		output = [NSJSONSerialization dataWithJSONObject:@{
			@"profile" : profile,
			@"page_a" : @(pages[0]),
			@"page_b" : @(pages[1]),
			@"rounds" : @(rounds),
			@"warmup_rounds" : @(warmup),
			@"entries" : @(entries),
			@"requests" : @(count),
			@"wall_ns" : @(wall),
			@"cpu_ns" : @(cpu),
			@"p50_ns" : @(percentile(samples, count, PERCENTILE_MEDIAN)),
			@"p95_ns" : @(percentile(samples, count, PERCENTILE_TAIL)),
			@"p99_ns" : @(percentile(samples, count, PERCENTILE_EXTREME)),
			@"read_calls" : @(reader.calls - reads),
			@"read_bytes" : @(reader.bytes - readBytes),
			@"allocations" : @(resource.allocations - allocations),
			@"baseline_core_bytes" : @(baselineBytes),
			@"peak_core_bytes" : @(resource.peakBytes),
			@"peak_rss_bytes" : @(usage.ru_maxrss),
			@"oracle" : @"pass",
			@"record_cache_entries" : @(limits.record_cache_entries),
			@"clock" : @"CLOCK_MONOTONIC_RAW",
			@"protocol" : @"legacy"
		}
							 options:0
							   error:&error];
		assert(output != nil && error == nil);
		[volume invalidate];
		assert(resource.liveBytes == 0);
		fwrite(output.bytes, 1, output.length, stdout);
		fputc('\n', stdout);
		free(samples);
	}
	return 0;
}
