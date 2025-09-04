/*
 * Minimal OpenSIPS module
 */

#include "../../sr_module.h"

static int mod_init(void);

struct module_exports exports = {
    "minimal",              /* module name */
    MOD_TYPE_DEFAULT,       /* class of this module */
    MODULE_VERSION,         /* version info */
    DEFAULT_DLFLAGS,        /* dlopen flags */
    0,                      /* load function */
    0,                      /* OpenSIPS module dependencies */
    0,                      /* exported functions */
    0,                      /* exported asynchronous functions */
    0,                      /* exported parameters */
    0,                      /* exported statistics */
    0,                      /* exported MI functions */
    0,                      /* exported pseudo-variables */
    0,                      /* exported transformations */
    0,                      /* extra processes */
    0,                      /* module pre-initialization function */
    mod_init,               /* module initialization function */
    0,                      /* response function */
    0,                      /* destroy function */
    0,                      /* per-child init function */
    0                       /* reload-ack function */
};

static int mod_init(void)
{
    return 0;
}