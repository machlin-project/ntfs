/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

/* An observer belongs to one volume. Its lock never waits for core or resource
 * I/O. Notifications only change future retention; they do not visit items. */
@interface NTFSReadCachePolicy : NSObject
- (void)start;
- (void)stop;
- (void)applyPressure:(dispatch_source_memorypressure_flags_t)flags;
@property(readonly) BOOL retentionActive;
/* Factory boundary for alternative notification sources. The returned source
 * must be suspended; this owner installs its handler, resumes and cancels it. */
- (dispatch_source_t)newPressureSource;
@end
