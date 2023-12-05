#include <string.h>
#include "ut.h"
#include "redact_pii.h"

int redacting_pii = 0;

inline const char* redact_pii(const char* input) { 
    return redacting_pii ? "****" : ZSW(input); 
}
