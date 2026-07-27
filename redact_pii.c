#include <string.h>
#include "str.h"
#include "ut.h"
#include "redact_pii.h"

int redact_pii_ = 0;
str redact_template = str_init("****");
int redact_mode = REDACT_REPLACE;
redact_log_format_t redact_fmt = {{NULL, 0}, {NULL, 0}};

#define REDACT_BUF_SIZE 512
#define SAFE_COPY_TO_BUFFER(_c, _len) \
	do { \
		size_t _n = (_len); \
		if (idx + _n < REDACT_BUF_SIZE) { \
			memcpy(buf + idx, (_c), _n); \
			idx += _n; \
		} else { \
			goto end; \
		} \
	} while (0)

inline const char* redact_pii(const char* input) {
	static __thread char buf[REDACT_BUF_SIZE];
	const char *safe = ZSW(input);
	size_t input_len = 0; 
	size_t idx = 0;

	if (!redact_pii_)
		return safe;

	input_len = strlen(safe);
	switch (redact_mode) {
	case REDACT_APPEND:
		SAFE_COPY_TO_BUFFER(safe, input_len);
		SAFE_COPY_TO_BUFFER(redact_template.s, redact_template.len);
		goto end;
	case REDACT_PREPEND:
		SAFE_COPY_TO_BUFFER(redact_template.s, redact_template.len);
		SAFE_COPY_TO_BUFFER(safe, input_len);
		goto end;
	case REDACT_FORMAT:
		if (redact_fmt.left.len > 0)
			SAFE_COPY_TO_BUFFER(redact_fmt.left.s, redact_fmt.left.len);
		SAFE_COPY_TO_BUFFER(safe, input_len);
		if (redact_fmt.right.len > 0)
			SAFE_COPY_TO_BUFFER(redact_fmt.right.s, redact_fmt.right.len);
		goto end;
	default:
		SAFE_COPY_TO_BUFFER(redact_template.s, redact_template.len);
		goto end;
	}
end:
	buf[idx] = '\0';
	return buf;
}
