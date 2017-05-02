#ifndef DRM_INTERRUPT_TYPES_H
#define DRM_INTERRUPT_TYPES_H

#include <linux/module.h>

// currently we need to support only these 2-interrupt types

#define DRM_DABORT_TYPE ((uint64_t)(0xDAB01))
#define DRM_PABORT_TYPE ((uint64_t)(0x9AB01))

// possible return value from handler functions
typedef enum {
    // continue execution on non-secure side.
    CONTINUE_NS_EXECUTION = 1,
    // continue execution on secure side.
    CONTINUE_S_EXECUTION,
    // error occured while handling the interrupts.
    ERROR_OCCURRED
} DRM_INT_RET_TYPE;


#endif
