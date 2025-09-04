#include "../../sr_module.h"
#include "../../dprint.h"
#include <unistd.h>

static int mod_init(void);
static void hello_process(int rank);

static proc_export_t procs[] = {
    {"Hello Process", 0, 0, hello_process, 1, 0},
    {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
    "evan_read_cpu",
    MOD_TYPE_DEFAULT,
    MODULE_VERSION,
    DEFAULT_DLFLAGS,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    procs,
    0, mod_init, 0, 0, 0, 0
};

static int mod_init(void)
{
    return 0;
}

static void hello_process(int rank)
{
    while(1) {
        LM_INFO("EVAN_HELLO LOGGING OUT \n");
        sleep(10);
    }
}