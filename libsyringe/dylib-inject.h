//
//  dylib-inject.h
//  libhooker-inject-test
//
//  Created by CoolStar on 6/2/20.
//  Copyright © 2020 coolstar. All rights reserved.
//

#ifndef dylib_inject_h
#define dylib_inject_h

#import <mach/mach.h>

kern_return_t LHInjectDylib(mach_port_t target, char *dylib, int argc, char *argv[]);

#endif /* dylib_inject_h */
