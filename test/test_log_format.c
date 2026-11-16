#include <tap.h>

#include "../str.h"
#include "../dprint.h"

#include "test_log_format.h"

void test_log_format(void)
{
	/* format names -> enum log_format */
	ok(parse_log_format(_str(LOG_PLAIN_NAME)) == LOG_FORMAT_PLAIN,
		"test-log-format-parse-0");
	ok(parse_log_format(_str(LOG_JSON_NAME)) == LOG_FORMAT_JSON,
		"test-log-format-parse-1");
	ok(parse_log_format(_str(LOG_JSON_CEE_NAME)) == LOG_FORMAT_JSON_CEE,
		"test-log-format-parse-2");
	ok(parse_log_format(_str("")) == -1, "test-log-format-parse-3");
	ok(parse_log_format(_str("bogus")) == -1, "test-log-format-parse-4");

	/* no override keeps the configured format */
	ok(resolve_log_format(LOG_FORMAT_PLAIN, LOG_FMT_OVR_NONE) ==
		LOG_FORMAT_PLAIN, "test-log-format-resolve-0");
	ok(resolve_log_format(LOG_FORMAT_JSON, LOG_FMT_OVR_NONE) ==
		LOG_FORMAT_JSON, "test-log-format-resolve-1");
	ok(resolve_log_format(LOG_FORMAT_JSON_CEE, LOG_FMT_OVR_NONE) ==
		LOG_FORMAT_JSON_CEE, "test-log-format-resolve-2");

	/* an override wins over any configured format */
	ok(resolve_log_format(LOG_FORMAT_JSON, LOG_FMT_OVR_PLAIN) ==
		LOG_FORMAT_PLAIN, "test-log-format-resolve-3");
	ok(resolve_log_format(LOG_FORMAT_PLAIN, LOG_FMT_OVR_JSON) ==
		LOG_FORMAT_JSON, "test-log-format-resolve-4");
	ok(resolve_log_format(LOG_FORMAT_PLAIN, LOG_FMT_OVR_JSON_CEE) ==
		LOG_FORMAT_JSON_CEE, "test-log-format-resolve-5");
	ok(resolve_log_format(LOG_FORMAT_JSON_CEE, LOG_FMT_OVR_JSON) ==
		LOG_FORMAT_JSON, "test-log-format-resolve-6");

	/* unknown override values fall back to the configured format */
	ok(resolve_log_format(LOG_FORMAT_JSON, (enum log_fmt_override)99) ==
		LOG_FORMAT_JSON, "test-log-format-resolve-7");
}
