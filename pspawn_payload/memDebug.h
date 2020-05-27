//
//  memDebug.h
//  test-pspawn-C
//
//  Created by CoolStar on 5/15/20.
//  Copyright © 2020 coolstar. All rights reserved.
//

#ifndef memDebug_h
#define memDebug_h

#if MEMDEBUG
#include <stdint.h>

void *userland_alloc(size_t size);
char *userland_strdup(char *str);
void userland_free(void *buf);

void userland_checkInit(void);
void userland_checkBuffers(void);
#else
#define userland_alloc malloc
#define userland_free free
#define userland_strdup strdup

#define userland_checkInit()
#define userland_checkBuffers()
#endif

#endif /* memDebug_h */
