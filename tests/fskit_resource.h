/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"

@interface TestReader : NSObject <NTFSBlockReader>
@property NSData *image;
@property BOOL shortRead;
@property BOOL failed;
@property(getter=isRevoked) BOOL revoked;
@property BOOL revokeDuringRead;
@property NSUInteger reads;
@property NSUInteger failReadAt;
/* Observe/refuse a physical interval without blocking unrelated metadata I/O. */
@property uint64_t observedStart;
@property uint64_t observedEnd;
@property NSUInteger observedReads;
@property BOOL refuseObservedReads;

/* Extend an authored resource to whole physical blocks without moving bytes. */
- (void)setAlignedImage:(NSData *)image;
@end

@interface FaultResource : NTFSResource
@property BOOL failAllocation;
@property NSUInteger allocations;
@property NSUInteger failAllocationAt;
@property NSUInteger liveAllocations;
@end
