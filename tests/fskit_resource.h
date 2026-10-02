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
@end

@interface FaultResource : NTFSResource
@property BOOL failAllocation;
@property NSUInteger allocations;
@property NSUInteger failAllocationAt;
@property NSUInteger liveAllocations;
@end
