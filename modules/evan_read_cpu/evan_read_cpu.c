/*
 * evan_read_cpu module
 */

#include "../../sr_module.h"
#include "../../timer.h"
#include "../../dprint.h"
#include <stdio.h>
#include <unistd.h>

static int mod_init(void);
static void mod_destroy(void);
static void cpu_monitor_process(int rank);

static proc_export_t procs[] = {
    {"CPU Monitor", 0, 0, cpu_monitor_process, 1, 0},
    {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
    "evan_read_cpu",        /* module name */
    MOD_TYPE_DEFAULT,       /* class of this module */
    MODULE_VERSION,
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
    procs,                  /* extra processes */
    0,                      /* module pre-initialization function */
    mod_init,               /* module initialization function */
    0,                      /* response function */
    mod_destroy,            /* destroy function */
    0,                      /* per-child init function */
    0                       /* reload-ack function */
};

static int mod_init(void)
{
    LM_INFO("evan_read_cpu module initialized\n");
    return 0;
}

static void mod_destroy(void)
{
    LM_INFO("evan_read_cpu module destroyed\n");
}

static void cpu_monitor_process(int rank)
{
    FILE *fp;
    char line[256];
    unsigned long user, nice, system, idle, total, used;
    float cpu_percent;
    
    LM_INFO("CPU monitor process started\n");
    
    while(1) {
        fp = fopen("/proc/stat", "r");
        if (fp && fgets(line, sizeof(line), fp)) {
            sscanf(line, "cpu %lu %lu %lu %lu", &user, &nice, &system, &idle);
            total = user + nice + system + idle;
            used = user + nice + system;
            cpu_percent = total > 0 ? (float)used * 100.0 / total : 0.0;
            LM_INFO("CPU Usage: %.2f%%\n", cpu_percent);
            fclose(fp);
        }
        sleep(10);
    }
}