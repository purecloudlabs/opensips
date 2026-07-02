#include <string.h>
#include <stdio.h>
#include "ut.h"
#include "redact_pii.h"

int redact_pii_ = 0;
char *redact_template = "****";
int redact_mode = REDACT_REPLACE;

inline const char* redact_pii(const char* input) {
    static char buf[512];
    const char *safe = ZSW(input);

    if (!redact_pii_)
        return safe;

    switch (redact_mode) {
    case REDACT_APPEND:
        snprintf(buf, sizeof(buf), "%s%s", safe, redact_template);
        return buf;
    case REDACT_PREPEND:
        snprintf(buf, sizeof(buf), "%s%s", redact_template, safe);
        return buf;
    case REDACT_FORMAT:
        snprintf(buf, sizeof(buf), redact_template, safe);
        return buf;
    case REDACT_REPLACE:
    default:
        return redact_template;
    }
}
