#include <string.h>
#include "ut.h"
#include "redact_pii.h"

int redact_pii = 0;

inline const char* redact_pii(const char* input) { 
    return redact_pii ? "****" : ZSW(input); 
}
