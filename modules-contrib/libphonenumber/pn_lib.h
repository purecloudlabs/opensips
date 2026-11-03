/*
 * libphonenumber module - C interface to Google's libphonenumber C++ library
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

/*
 * This header is shared between the C module code and the C++ wrapper. It
 * must not depend on any OpenSIPS or libphonenumber header, so that each
 * side can be compiled with its own toolchain and include paths.
 *
 * All string inputs are passed as (pointer, length) pairs and need not be
 * NUL terminated. String outputs are returned through a pn_res structure
 * pointing to storage owned by the wrapper; the value is valid until the
 * next call into this API (OpenSIPS workers are single threaded).
 */

#ifndef _LIBPHONENUMBER_PN_LIB_H_
#define _LIBPHONENUMBER_PN_LIB_H_

#ifdef __cplusplus
extern "C" {
#endif

/* return codes of the pn_* wrapper calls */
#define PN_OK            0  /* success, result available */
#define PN_FALSE        -1  /* success, negative answer / empty result */
#define PN_ERR_PARSE    -2  /* the input number could not be parsed */
#define PN_ERR_ARG      -3  /* invalid argument (unknown region, type, ...) */
#define PN_ERR_INTERNAL -4  /* unexpected library failure */

/* values mirror i18n::phonenumbers::PhoneNumberUtil::PhoneNumberFormat */
enum pn_format {
	PN_FMT_E164 = 0,
	PN_FMT_INTERNATIONAL,
	PN_FMT_NATIONAL,
	PN_FMT_RFC3966,
};

/* values mirror i18n::phonenumbers::PhoneNumberUtil::PhoneNumberType */
enum pn_type {
	PN_TYPE_FIXED_LINE = 0,
	PN_TYPE_MOBILE,
	PN_TYPE_FIXED_LINE_OR_MOBILE,
	PN_TYPE_TOLL_FREE,
	PN_TYPE_PREMIUM_RATE,
	PN_TYPE_SHARED_COST,
	PN_TYPE_VOIP,
	PN_TYPE_PERSONAL_NUMBER,
	PN_TYPE_PAGER,
	PN_TYPE_UAN,
	PN_TYPE_VOICEMAIL,
	PN_TYPE_UNKNOWN,
};

/* values mirror i18n::phonenumbers::PhoneNumberUtil::MatchType */
enum pn_match {
	PN_MATCH_INVALID_NUMBER = 0,
	PN_MATCH_NO_MATCH,
	PN_MATCH_SHORT_NSN_MATCH,
	PN_MATCH_NSN_MATCH,
	PN_MATCH_EXACT_MATCH,
};

/* values mirror i18n::phonenumbers::PhoneNumberUtil::ValidationResult */
enum pn_validation {
	PN_VAL_IS_POSSIBLE = 0,
	PN_VAL_IS_POSSIBLE_LOCAL_ONLY,
	PN_VAL_INVALID_COUNTRY_CODE,
	PN_VAL_TOO_SHORT,
	PN_VAL_INVALID_LENGTH,
	PN_VAL_TOO_LONG,
};

/* a non-owning (pointer, length) string */
typedef struct pn_str {
	const char *s;
	int len;
} pn_str;

/* callback used to forward libphonenumber's own log messages */
typedef void (*pn_log_f)(const char *msg, int len);

/* must be called once, before forking, from mod_init() */
int pn_init(pn_log_f log_func);

/*
 * Region arguments: a NULL/empty region means "unknown region" (ZZ), in
 * which case the number must be in international (+CC...) format.
 * Region codes are case insensitive.
 */

/* string transformations, no parsing involved */
int pn_convert_alpha_characters(const pn_str *number, pn_str *out);
int pn_normalize_digits_only(const pn_str *number, pn_str *out);
int pn_normalize_diallable_chars_only(const pn_str *number, pn_str *out);
int pn_is_alpha_number(const pn_str *number);

/* formatting */
int pn_format(const pn_str *number, const pn_str *region,
		enum pn_format fmt, pn_str *out);
int pn_format_in_original_format(const pn_str *number, const pn_str *region,
		const pn_str *calling_from, pn_str *out);
int pn_format_national_with_carrier_code(const pn_str *number,
		const pn_str *region, const pn_str *carrier_code, pn_str *out);
int pn_format_national_with_preferred_carrier_code(const pn_str *number,
		const pn_str *region, const pn_str *fallback_carrier_code, pn_str *out);
int pn_format_for_mobile_dialing(const pn_str *number, const pn_str *region,
		const pn_str *calling_from, int with_formatting, pn_str *out);
int pn_format_out_of_country(const pn_str *number, const pn_str *region,
		const pn_str *calling_from, pn_str *out);
int pn_format_out_of_country_keeping_alpha(const pn_str *number,
		const pn_str *region, const pn_str *calling_from, pn_str *out);
int pn_truncate_too_long_number(const pn_str *number, const pn_str *region,
		pn_str *out);

/* number information */
int pn_get_country_code(const pn_str *number, const pn_str *region, int *out);
int pn_get_national_significant_number(const pn_str *number,
		const pn_str *region, pn_str *out);
int pn_get_length_of_geographical_area_code(const pn_str *number,
		const pn_str *region, int *out);
int pn_get_length_of_national_destination_code(const pn_str *number,
		const pn_str *region, int *out);
int pn_get_number_type(const pn_str *number, const pn_str *region,
		enum pn_type *out);
int pn_get_region_code_for_number(const pn_str *number, const pn_str *region,
		pn_str *out);

/* validation */
int pn_is_valid_number(const pn_str *number, const pn_str *region);
int pn_is_valid_number_for_region(const pn_str *number, const pn_str *region,
		const pn_str *for_region);
int pn_is_possible_number(const pn_str *number, const pn_str *region);
int pn_is_possible_number_with_reason(const pn_str *number,
		const pn_str *region, enum pn_validation *out);
int pn_is_possible_number_for_type(const pn_str *number, const pn_str *region,
		enum pn_type type);
int pn_is_possible_number_for_string(const pn_str *number,
		const pn_str *dialing_from);
int pn_can_be_internationally_dialled(const pn_str *number,
		const pn_str *region);
int pn_is_number_geographical(const pn_str *number, const pn_str *region);
int pn_is_number_match(const pn_str *number1, const pn_str *region1,
		const pn_str *number2, const pn_str *region2, enum pn_match *out);

/* region / country calling code metadata */
int pn_get_country_code_for_region(const pn_str *region, int *out);
int pn_get_region_code_for_country_code(int country_code, pn_str *out);
int pn_get_region_codes_for_country_code(int country_code, pn_str *out);
int pn_get_country_mobile_token(int country_code, pn_str *out);
int pn_get_ndd_prefix_for_region(const pn_str *region, int strip_non_digits,
		pn_str *out);
int pn_is_nanpa_country(const pn_str *region);
int pn_get_example_number(const pn_str *region, int use_type,
		enum pn_type type, pn_str *out);

/* short numbers (emergency, service codes) */
int pn_is_emergency_number(const pn_str *number, const pn_str *region);
int pn_connects_to_emergency_number(const pn_str *number,
		const pn_str *region);
int pn_is_valid_short_number(const pn_str *number, const pn_str *region);
int pn_is_possible_short_number(const pn_str *number, const pn_str *region);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPHONENUMBER_PN_LIB_H_ */
