#include <string.h>
#include "ut.h"
#include "redact_pii.h"

int redact_pii_ = 0;
char *redact_template = "****";
int redact_mode = REDACT_REPLACE;
redact_log_format_t redact_fmt = {{NULL, 0}, {NULL, 0}};

#define REDACT_BUF_SIZE 512

inline const char* redact_pii(const char* input) {
	static char buf[REDACT_BUF_SIZE];
	const char *safe = ZSW(input);
	size_t input_len, idx;

	if (!redact_pii_)
		return safe;

	switch (redact_mode) {
	case REDACT_REPLACE:
		return redact_template;
	case REDACT_APPEND:
		input_len = strlen(safe);
		idx = 0;
		memcpy(buf + idx, safe, input_len);
		idx += input_len;
		memcpy(buf + idx, redact_template, strlen(redact_template));
		idx += strlen(redact_template);
		buf[idx] = '\0';
		return buf;
	case REDACT_PREPEND:
		input_len = strlen(safe);
		idx = 0;
		memcpy(buf + idx, redact_template, strlen(redact_template));
		idx += strlen(redact_template);
		memcpy(buf + idx, safe, input_len);
		idx += input_len;
		buf[idx] = '\0';
		return buf;
	case REDACT_FORMAT:
		input_len = strlen(safe);
		idx = 0;
		if (redact_fmt.left.len > 0) {
			memcpy(buf + idx, redact_fmt.left.s, redact_fmt.left.len);
			idx += redact_fmt.left.len;
		}
		memcpy(buf + idx, safe, input_len);
		idx += input_len;
		if (redact_fmt.right.len > 0) {
			memcpy(buf + idx, redact_fmt.right.s, redact_fmt.right.len);
			idx += redact_fmt.right.len;
		}
		buf[idx] = '\0';
		return buf;
	default:
		return redact_template;
	}
}
