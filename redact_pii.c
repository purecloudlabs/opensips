#include <string.h>
#include "ut.h"

int redact_sip_pii = 0;

inline char *redact_pii(const char *input){
    return redact_sip_pii ? ZSRW(input) : ZSW(input);
}
