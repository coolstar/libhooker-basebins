//
//  dylib-inject.h
//  dylib-inject
//
//  Created by CoolStar on 2/5/20.
//  Copyright © 2020 coolstar. All rights reserved.
//

#include <mach/mach.h>

#ifndef dylib_inject_h
#define dylib_inject_h

kern_return_t inject_dylib(mach_port_t target, char *dylib);

#endif /* dylib_inject_h */
