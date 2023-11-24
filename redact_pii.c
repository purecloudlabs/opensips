#include <string.h> 
int redact_sip_pii = 1;

char* redact_pii(char* input) {
    if (input == NULL) {
        return ""; 
    }

    if (redact_sip_pii) {
        strcpy(input, "****");
    }
    return input;
}
