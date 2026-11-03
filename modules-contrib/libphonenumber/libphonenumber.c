/*
 * libphonenumber module - parse, format and validate phone numbers using
 * Google's libphonenumber library
 *
 * Copyright (C) 2023-2026 Genesys Cloud Services, Inc.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <strings.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../str.h"
#include "../../ut.h"

#include "pn_lib.h"

/* script return codes */
#define RET_OK            1
#define RET_FALSE        -1
#define RET_ERR_PARSE    -2
#define RET_ERR_ARG      -3
#define RET_ERR_INTERNAL -4

static str default_region = str_init("ZZ");

static int mod_init(void);
static int fixup_check_wrvar(void **param);

/* string operations */
static int w_convert_alpha(struct sip_msg *msg, str *number, pv_spec_t *out);
static int w_normalize_digits(struct sip_msg *msg, str *number, pv_spec_t *out);
static int w_normalize_diallable(struct sip_msg *msg, str *number,
		pv_spec_t *out);
static int w_is_alpha_number(struct sip_msg *msg, str *number);

/* formatting */
static int w_format(struct sip_msg *msg, str *number, str *fmt,
		pv_spec_t *out, str *region);
static int w_format_original(struct sip_msg *msg, str *number,
		str *calling_from, pv_spec_t *out, str *region);
static int w_format_carrier(struct sip_msg *msg, str *number,
		str *carrier_code, pv_spec_t *out, str *region);
static int w_format_pref_carrier(struct sip_msg *msg, str *number,
		str *carrier_code, pv_spec_t *out, str *region);
static int w_format_mobile_dialing(struct sip_msg *msg, str *number,
		str *calling_from, int *with_formatting, pv_spec_t *out, str *region);
static int w_format_out_of_country(struct sip_msg *msg, str *number,
		str *calling_from, pv_spec_t *out, str *region);
static int w_format_out_of_country_alpha(struct sip_msg *msg, str *number,
		str *calling_from, pv_spec_t *out, str *region);
static int w_truncate_too_long(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region);

/* number information */
static int w_get_country_code(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region);
static int w_get_nsn(struct sip_msg *msg, str *number, pv_spec_t *out,
		str *region);
static int w_get_geo_area_code_len(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region);
static int w_get_ndc_len(struct sip_msg *msg, str *number, pv_spec_t *out,
		str *region);
static int w_get_number_type(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region);
static int w_get_region_code_for_number(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region);

/* validation */
static int w_is_valid_number(struct sip_msg *msg, str *number, str *region);
static int w_is_valid_number_for_region(struct sip_msg *msg, str *number,
		str *for_region, str *region);
static int w_is_possible_number(struct sip_msg *msg, str *number,
		str *region);
static int w_is_possible_number_with_reason(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region);
static int w_is_possible_number_for_type(struct sip_msg *msg, str *number,
		str *type, str *region);
static int w_is_possible_number_for_string(struct sip_msg *msg, str *number,
		str *dialing_from);
static int w_can_be_intl_dialled(struct sip_msg *msg, str *number,
		str *region);
static int w_is_number_geographical(struct sip_msg *msg, str *number,
		str *region);
static int w_is_number_match(struct sip_msg *msg, str *number1, str *number2,
		str *region1, str *region2, pv_spec_t *out);

/* region / country calling code metadata */
static int w_get_cc_for_region(struct sip_msg *msg, str *region,
		pv_spec_t *out);
static int w_get_region_for_cc(struct sip_msg *msg, int *cc, pv_spec_t *out);
static int w_get_regions_for_cc(struct sip_msg *msg, int *cc, pv_spec_t *out);
static int w_get_mobile_token(struct sip_msg *msg, int *cc, pv_spec_t *out);
static int w_get_ndd_prefix(struct sip_msg *msg, str *region,
		int *strip_non_digits, pv_spec_t *out);
static int w_is_nanpa_country(struct sip_msg *msg, str *region);
static int w_get_example_number(struct sip_msg *msg, str *region,
		pv_spec_t *out, str *type);

/* short numbers */
static int w_is_emergency_number(struct sip_msg *msg, str *number,
		str *region);
static int w_connects_to_emergency_number(struct sip_msg *msg, str *number,
		str *region);
static int w_is_valid_short_number(struct sip_msg *msg, str *number,
		str *region);
static int w_is_possible_short_number(struct sip_msg *msg, str *number,
		str *region);

#define P_STR      {CMD_PARAM_STR, 0, 0}
#define P_STR_OPT  {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}
#define P_INT      {CMD_PARAM_INT, 0, 0}
#define P_OUT      {CMD_PARAM_VAR, fixup_check_wrvar, 0}
#define P_OUT_OPT  {CMD_PARAM_VAR | CMD_PARAM_OPT, fixup_check_wrvar, 0}
#define P_END      {0, 0, 0}

static const cmd_export_t cmds[] = {
	{"pn_convert_alpha_characters_in_number", (cmd_function)w_convert_alpha,
		{P_STR, P_OUT, P_END}, ALL_ROUTES},
	{"pn_normalize_digits_only", (cmd_function)w_normalize_digits,
		{P_STR, P_OUT, P_END}, ALL_ROUTES},
	{"pn_normalize_diallable_chars_only", (cmd_function)w_normalize_diallable,
		{P_STR, P_OUT, P_END}, ALL_ROUTES},
	{"pn_is_alpha_number", (cmd_function)w_is_alpha_number,
		{P_STR, P_END}, ALL_ROUTES},

	{"pn_format", (cmd_function)w_format,
		{P_STR, P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_format_in_original_format", (cmd_function)w_format_original,
		{P_STR, P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_format_national_number_with_carrier_code",
		(cmd_function)w_format_carrier,
		{P_STR, P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_format_national_number_with_preferred_carrier_code",
		(cmd_function)w_format_pref_carrier,
		{P_STR, P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_format_number_for_mobile_dialing",
		(cmd_function)w_format_mobile_dialing,
		{P_STR, P_STR, P_INT, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_format_out_of_country_calling_number",
		(cmd_function)w_format_out_of_country,
		{P_STR, P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_format_out_of_country_keeping_alpha_chars",
		(cmd_function)w_format_out_of_country_alpha,
		{P_STR, P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_truncate_too_long_number", (cmd_function)w_truncate_too_long,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},

	{"pn_get_country_code", (cmd_function)w_get_country_code,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_get_national_significant_number", (cmd_function)w_get_nsn,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_get_length_of_geographical_area_code",
		(cmd_function)w_get_geo_area_code_len,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_get_length_of_national_destination_code",
		(cmd_function)w_get_ndc_len,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_get_number_type", (cmd_function)w_get_number_type,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_get_region_code_for_number",
		(cmd_function)w_get_region_code_for_number,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},

	{"pn_is_valid_number", (cmd_function)w_is_valid_number,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_valid_number_for_region",
		(cmd_function)w_is_valid_number_for_region,
		{P_STR, P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_possible_number", (cmd_function)w_is_possible_number,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_possible_number_with_reason",
		(cmd_function)w_is_possible_number_with_reason,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_possible_number_for_type",
		(cmd_function)w_is_possible_number_for_type,
		{P_STR, P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_possible_number_for_string",
		(cmd_function)w_is_possible_number_for_string,
		{P_STR, P_STR, P_END}, ALL_ROUTES},
	{"pn_can_be_internationally_dialled", (cmd_function)w_can_be_intl_dialled,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_number_geographical", (cmd_function)w_is_number_geographical,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_number_match", (cmd_function)w_is_number_match,
		{P_STR, P_STR, P_STR_OPT, P_STR_OPT, P_OUT_OPT, P_END}, ALL_ROUTES},

	{"pn_get_country_code_for_region", (cmd_function)w_get_cc_for_region,
		{P_STR, P_OUT, P_END}, ALL_ROUTES},
	{"pn_get_region_code_for_country_code", (cmd_function)w_get_region_for_cc,
		{P_INT, P_OUT, P_END}, ALL_ROUTES},
	{"pn_get_region_codes_for_country_code",
		(cmd_function)w_get_regions_for_cc,
		{P_INT, P_OUT, P_END}, ALL_ROUTES},
	{"pn_get_country_mobile_token", (cmd_function)w_get_mobile_token,
		{P_INT, P_OUT, P_END}, ALL_ROUTES},
	{"pn_get_ndd_prefix_for_region", (cmd_function)w_get_ndd_prefix,
		{P_STR, P_INT, P_OUT, P_END}, ALL_ROUTES},
	{"pn_is_nanpa_country", (cmd_function)w_is_nanpa_country,
		{P_STR, P_END}, ALL_ROUTES},
	{"pn_get_example_number", (cmd_function)w_get_example_number,
		{P_STR, P_OUT, P_STR_OPT, P_END}, ALL_ROUTES},

	{"pn_is_emergency_number", (cmd_function)w_is_emergency_number,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_connects_to_emergency_number",
		(cmd_function)w_connects_to_emergency_number,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_valid_short_number", (cmd_function)w_is_valid_short_number,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},
	{"pn_is_possible_short_number", (cmd_function)w_is_possible_short_number,
		{P_STR, P_STR_OPT, P_END}, ALL_ROUTES},

	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"default_region", STR_PARAM, &default_region.s},
	{0, 0, 0}
};

struct module_exports exports = {
	"libphonenumber", /* module's name */
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,   /* module's version */
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,                /* load function */
	0,                /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	0,                /* exported async functions */
	params,           /* param exports */
	0,                /* exported statistics */
	0,                /* exported MI functions */
	0,                /* exported pseudo-variables */
	0,                /* exported transformations */
	0,                /* extra processes */
	0,                /* module pre-initialization function */
	mod_init,         /* module initialization function */
	0,                /* reply processing function */
	0,                /* destroy function */
	0,                /* per-child init function */
	0                 /* reload confirm function */
};

/* names exposed to the script, indexed by the pn_lib.h enum values */
static const str format_names[] = {
	str_init("E164"),
	str_init("INTERNATIONAL"),
	str_init("NATIONAL"),
	str_init("RFC3966"),
};

static const str type_names[] = {
	str_init("FIXED_LINE"),
	str_init("MOBILE"),
	str_init("FIXED_LINE_OR_MOBILE"),
	str_init("TOLL_FREE"),
	str_init("PREMIUM_RATE"),
	str_init("SHARED_COST"),
	str_init("VOIP"),
	str_init("PERSONAL_NUMBER"),
	str_init("PAGER"),
	str_init("UAN"),
	str_init("VOICEMAIL"),
	str_init("UNKNOWN"),
};

static const str match_names[] = {
	str_init("INVALID_NUMBER"),
	str_init("NO_MATCH"),
	str_init("SHORT_NSN_MATCH"),
	str_init("NSN_MATCH"),
	str_init("EXACT_MATCH"),
};

static const str validation_names[] = {
	str_init("IS_POSSIBLE"),
	str_init("IS_POSSIBLE_LOCAL_ONLY"),
	str_init("INVALID_COUNTRY_CODE"),
	str_init("TOO_SHORT"),
	str_init("INVALID_LENGTH"),
	str_init("TOO_LONG"),
};

static void pn_log(const char *msg, int len)
{
	LM_WARN("libphonenumber: %.*s\n", len, msg);
}

static int mod_init(void)
{
	LM_INFO("initializing...\n");

	default_region.len = default_region.s ? strlen(default_region.s) : 0;

	/* load the metadata once, before forking, so that all the
	 * processes share it */
	if (pn_init(pn_log) != PN_OK) {
		LM_ERR("failed to initialize libphonenumber\n");
		return -1;
	}

	if (default_region.len) {
		int cc;
		pn_str r = {default_region.s, default_region.len};

		if (pn_get_country_code_for_region(&r, &cc) != PN_OK &&
				strcasecmp(default_region.s, "ZZ") != 0) {
			LM_ERR("invalid default_region <%.*s>\n",
				default_region.len, default_region.s);
			return -1;
		}
	}

	return 0;
}

static int fixup_check_wrvar(void **param)
{
	if (((pv_spec_t *)*param)->setf == NULL) {
		LM_ERR("output parameter must be a writable variable\n");
		return E_SCRIPT;
	}
	return 0;
}

static inline pn_str to_pn(const str *s)
{
	pn_str r = {NULL, 0};

	if (s) {
		r.s = s->s;
		r.len = s->len;
	}
	return r;
}

/* the region to parse national numbers against: the script provided one,
 * or the module's default_region */
static inline pn_str to_region(const str *s)
{
	return (s && s->len > 0) ? to_pn(s) : to_pn(&default_region);
}

static int lookup_name(const str *names, int n, const str *value)
{
	int i;

	if (!value || value->len <= 0)
		return -1;

	for (i = 0; i < n; i++)
		if (names[i].len == value->len &&
				strncasecmp(names[i].s, value->s, value->len) == 0)
			return i;

	/* numeric values are still accepted, for convenience */
	if (str2sint(value, &i) == 0 && i >= 0 && i < n)
		return i;

	return -1;
}

static int pn_ret(int rc)
{
	switch (rc) {
	case PN_OK:
		return RET_OK;
	case PN_FALSE:
		return RET_FALSE;
	case PN_ERR_PARSE:
		LM_DBG("failed to parse phone number\n");
		return RET_ERR_PARSE;
	case PN_ERR_ARG:
		LM_DBG("invalid argument\n");
		return RET_ERR_ARG;
	default:
		LM_ERR("internal libphonenumber error\n");
		return RET_ERR_INTERNAL;
	}
}

static int set_out_str(struct sip_msg *msg, pv_spec_t *out, const str *val)
{
	pv_value_t v;

	v.rs = *val;
	v.flags = PV_VAL_STR;

	if (pv_set_value(msg, out, 0, &v) != 0) {
		LM_ERR("failed to set the output variable\n");
		return RET_ERR_INTERNAL;
	}
	return RET_OK;
}

static int set_out_int(struct sip_msg *msg, pv_spec_t *out, int val)
{
	pv_value_t v;

	v.rs.s = NULL;
	v.rs.len = 0;
	v.ri = val;
	v.flags = PV_VAL_INT | PV_TYPE_INT;

	if (pv_set_value(msg, out, 0, &v) != 0) {
		LM_ERR("failed to set the output variable\n");
		return RET_ERR_INTERNAL;
	}
	return RET_OK;
}

/* sets the output variable only if the lookup succeeded */
static int ret_str(struct sip_msg *msg, pv_spec_t *out, int rc,
		const pn_str *res)
{
	str s;

	if (rc != PN_OK)
		return pn_ret(rc);

	s.s = (char *)res->s;
	s.len = res->len;
	return set_out_str(msg, out, &s);
}

static int ret_int(struct sip_msg *msg, pv_spec_t *out, int rc, int res)
{
	if (rc != PN_OK)
		return pn_ret(rc);
	return set_out_int(msg, out, res);
}

static int ret_name(struct sip_msg *msg, pv_spec_t *out, const str *names,
		int n, int idx)
{
	if (idx < 0 || idx >= n) {
		LM_BUG("unexpected libphonenumber value %d\n", idx);
		return RET_ERR_INTERNAL;
	}
	return set_out_str(msg, out, &names[idx]);
}

/*
 * string operations
 */

static int w_convert_alpha(struct sip_msg *msg, str *number, pv_spec_t *out)
{
	pn_str n = to_pn(number), res;
	return ret_str(msg, out, pn_convert_alpha_characters(&n, &res), &res);
}

static int w_normalize_digits(struct sip_msg *msg, str *number, pv_spec_t *out)
{
	pn_str n = to_pn(number), res;
	return ret_str(msg, out, pn_normalize_digits_only(&n, &res), &res);
}

static int w_normalize_diallable(struct sip_msg *msg, str *number,
		pv_spec_t *out)
{
	pn_str n = to_pn(number), res;
	return ret_str(msg, out, pn_normalize_diallable_chars_only(&n, &res), &res);
}

static int w_is_alpha_number(struct sip_msg *msg, str *number)
{
	pn_str n = to_pn(number);
	return pn_ret(pn_is_alpha_number(&n));
}

/*
 * formatting
 */

static int w_format(struct sip_msg *msg, str *number, str *fmt,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region), res;
	int f = lookup_name(format_names,
		sizeof format_names / sizeof *format_names, fmt);

	if (f < 0) {
		LM_ERR("unknown phone number format <%.*s>\n", fmt->len, fmt->s);
		return RET_ERR_ARG;
	}
	return ret_str(msg, out, pn_format(&n, &r, (enum pn_format)f, &res), &res);
}

static int w_format_original(struct sip_msg *msg, str *number,
		str *calling_from, pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region),
		c = to_pn(calling_from), res;
	return ret_str(msg, out,
		pn_format_in_original_format(&n, &r, &c, &res), &res);
}

static int w_format_carrier(struct sip_msg *msg, str *number,
		str *carrier_code, pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region),
		c = to_pn(carrier_code), res;
	return ret_str(msg, out,
		pn_format_national_with_carrier_code(&n, &r, &c, &res), &res);
}

static int w_format_pref_carrier(struct sip_msg *msg, str *number,
		str *carrier_code, pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region),
		c = to_pn(carrier_code), res;
	return ret_str(msg, out,
		pn_format_national_with_preferred_carrier_code(&n, &r, &c, &res),
		&res);
}

static int w_format_mobile_dialing(struct sip_msg *msg, str *number,
		str *calling_from, int *with_formatting, pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region),
		c = to_pn(calling_from), res;
	return ret_str(msg, out, pn_format_for_mobile_dialing(&n, &r, &c,
		*with_formatting, &res), &res);
}

static int w_format_out_of_country(struct sip_msg *msg, str *number,
		str *calling_from, pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region),
		c = to_pn(calling_from), res;
	return ret_str(msg, out,
		pn_format_out_of_country(&n, &r, &c, &res), &res);
}

static int w_format_out_of_country_alpha(struct sip_msg *msg, str *number,
		str *calling_from, pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region),
		c = to_pn(calling_from), res;
	return ret_str(msg, out,
		pn_format_out_of_country_keeping_alpha(&n, &r, &c, &res), &res);
}

static int w_truncate_too_long(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region), res;
	return ret_str(msg, out, pn_truncate_too_long_number(&n, &r, &res), &res);
}

/*
 * number information
 */

static int w_get_country_code(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	int res = 0, rc;

	rc = pn_get_country_code(&n, &r, &res);
	return ret_int(msg, out, rc, res);
}

static int w_get_nsn(struct sip_msg *msg, str *number, pv_spec_t *out,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region), res;
	return ret_str(msg, out,
		pn_get_national_significant_number(&n, &r, &res), &res);
}

static int w_get_geo_area_code_len(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	int res = 0, rc;

	rc = pn_get_length_of_geographical_area_code(&n, &r, &res);
	return ret_int(msg, out, rc, res);
}

static int w_get_ndc_len(struct sip_msg *msg, str *number, pv_spec_t *out,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	int res = 0, rc;

	rc = pn_get_length_of_national_destination_code(&n, &r, &res);
	return ret_int(msg, out, rc, res);
}

static int w_get_number_type(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	enum pn_type t;
	int rc = pn_get_number_type(&n, &r, &t);

	if (rc != PN_OK)
		return pn_ret(rc);
	return ret_name(msg, out, type_names,
		sizeof type_names / sizeof *type_names, t);
}

static int w_get_region_code_for_number(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region), res;
	return ret_str(msg, out,
		pn_get_region_code_for_number(&n, &r, &res), &res);
}

/*
 * validation
 */

static int w_is_valid_number(struct sip_msg *msg, str *number, str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_is_valid_number(&n, &r));
}

static int w_is_valid_number_for_region(struct sip_msg *msg, str *number,
		str *for_region, str *region)
{
	pn_str n = to_pn(number), r = to_region(region), f = to_pn(for_region);
	return pn_ret(pn_is_valid_number_for_region(&n, &r, &f));
}

static int w_is_possible_number(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_is_possible_number(&n, &r));
}

static int w_is_possible_number_with_reason(struct sip_msg *msg, str *number,
		pv_spec_t *out, str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	enum pn_validation v;
	int rc = pn_is_possible_number_with_reason(&n, &r, &v), ret;

	if (rc != PN_OK && rc != PN_FALSE)
		return pn_ret(rc);

	ret = ret_name(msg, out, validation_names,
		sizeof validation_names / sizeof *validation_names, v);
	return ret < 0 ? ret : pn_ret(rc);
}

static int w_is_possible_number_for_type(struct sip_msg *msg, str *number,
		str *type, str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	int t = lookup_name(type_names, sizeof type_names / sizeof *type_names,
		type);

	if (t < 0) {
		LM_ERR("unknown phone number type <%.*s>\n", type->len, type->s);
		return RET_ERR_ARG;
	}
	return pn_ret(pn_is_possible_number_for_type(&n, &r, (enum pn_type)t));
}

static int w_is_possible_number_for_string(struct sip_msg *msg, str *number,
		str *dialing_from)
{
	pn_str n = to_pn(number), d = to_pn(dialing_from);
	return pn_ret(pn_is_possible_number_for_string(&n, &d));
}

static int w_can_be_intl_dialled(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_can_be_internationally_dialled(&n, &r));
}

static int w_is_number_geographical(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_is_number_geographical(&n, &r));
}

static int w_is_number_match(struct sip_msg *msg, str *number1, str *number2,
		str *region1, str *region2, pv_spec_t *out)
{
	pn_str n1 = to_pn(number1), n2 = to_pn(number2),
		r1 = to_region(region1), r2 = to_region(region2);
	enum pn_match m = PN_MATCH_INVALID_NUMBER;
	int rc = pn_is_number_match(&n1, &r1, &n2, &r2, &m), ret;

	if (rc == PN_ERR_INTERNAL)
		return pn_ret(rc);

	if (out) {
		ret = ret_name(msg, out, match_names,
			sizeof match_names / sizeof *match_names, m);
		if (ret < 0)
			return ret;
	}
	return pn_ret(rc);
}

/*
 * region / country calling code metadata
 */

static int w_get_cc_for_region(struct sip_msg *msg, str *region,
		pv_spec_t *out)
{
	pn_str r = to_pn(region);
	int res = 0, rc;

	rc = pn_get_country_code_for_region(&r, &res);
	return ret_int(msg, out, rc, res);
}

static int w_get_region_for_cc(struct sip_msg *msg, int *cc, pv_spec_t *out)
{
	pn_str res;
	return ret_str(msg, out,
		pn_get_region_code_for_country_code(*cc, &res), &res);
}

static int w_get_regions_for_cc(struct sip_msg *msg, int *cc, pv_spec_t *out)
{
	pn_str res;
	return ret_str(msg, out,
		pn_get_region_codes_for_country_code(*cc, &res), &res);
}

static int w_get_mobile_token(struct sip_msg *msg, int *cc, pv_spec_t *out)
{
	pn_str res;
	return ret_str(msg, out, pn_get_country_mobile_token(*cc, &res), &res);
}

static int w_get_ndd_prefix(struct sip_msg *msg, str *region,
		int *strip_non_digits, pv_spec_t *out)
{
	pn_str r = to_pn(region), res;
	return ret_str(msg, out,
		pn_get_ndd_prefix_for_region(&r, *strip_non_digits, &res), &res);
}

static int w_is_nanpa_country(struct sip_msg *msg, str *region)
{
	pn_str r = to_pn(region);
	return pn_ret(pn_is_nanpa_country(&r));
}

static int w_get_example_number(struct sip_msg *msg, str *region,
		pv_spec_t *out, str *type)
{
	pn_str r = to_pn(region), res;
	int t = 0;

	if (type) {
		t = lookup_name(type_names, sizeof type_names / sizeof *type_names,
			type);
		if (t < 0) {
			LM_ERR("unknown phone number type <%.*s>\n", type->len, type->s);
			return RET_ERR_ARG;
		}
	}
	return ret_str(msg, out,
		pn_get_example_number(&r, type != NULL, (enum pn_type)t, &res), &res);
}

/*
 * short numbers
 */

static int w_is_emergency_number(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_is_emergency_number(&n, &r));
}

static int w_connects_to_emergency_number(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_connects_to_emergency_number(&n, &r));
}

static int w_is_valid_short_number(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_is_valid_short_number(&n, &r));
}

static int w_is_possible_short_number(struct sip_msg *msg, str *number,
		str *region)
{
	pn_str n = to_pn(number), r = to_region(region);
	return pn_ret(pn_is_possible_short_number(&n, &r));
}
