/*
 * libphonenumber module - C++ wrapper over Google's libphonenumber
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

#include <algorithm>
#include <cctype>
#include <list>
#include <set>
#include <string>

#include <phonenumbers/logger.h>
#include <phonenumbers/phonenumber.pb.h>
#include <phonenumbers/phonenumberutil.h>
#include <phonenumbers/shortnumberinfo.h>

#include "pn_lib.h"

using i18n::phonenumbers::Logger;
using i18n::phonenumbers::PhoneNumber;
using i18n::phonenumbers::PhoneNumberUtil;
using i18n::phonenumbers::ShortNumberInfo;

#define PN_UNKNOWN_REGION "ZZ"

namespace {

const PhoneNumberUtil *util;
const ShortNumberInfo *short_info;

/* storage for string results handed back to the C side */
std::string result;

/* collects the pieces of a libphonenumber log line and forwards it as a
 * single message once complete (LoggerHandler terminates lines with "\n") */
class OpenSIPSLogger : public Logger {
public:
	explicit OpenSIPSLogger(pn_log_f f) : log_func(f) {}

	void WriteMessage(const std::string &msg) override {
		if (msg == "\n") {
			if (log_func && !line.empty())
				log_func(line.data(), (int)line.size());
			line.clear();
			return;
		}
		if (!line.empty())
			line += ' ';
		line += msg;
	}

private:
	pn_log_f log_func;
	std::string line;
};

inline std::string to_string(const pn_str *s)
{
	if (!s || !s->s || s->len <= 0)
		return std::string();
	return std::string(s->s, s->len);
}

inline std::string to_region(const pn_str *s)
{
	std::string r = to_string(s);
	if (r.empty())
		return PN_UNKNOWN_REGION;
	std::transform(r.begin(), r.end(), r.begin(),
		[](unsigned char c) { return std::toupper(c); });
	return r;
}

inline int set_result(pn_str *out)
{
	out->s = result.data();
	out->len = (int)result.size();
	return result.empty() ? PN_FALSE : PN_OK;
}

inline int set_result(pn_str *out, const std::string &s)
{
	result = s;
	return set_result(out);
}

/* raw input is needed by FormatInOriginalFormat() and
 * FormatOutOfCountryKeepingAlphaChars() */
int parse(const pn_str *number, const pn_str *region, PhoneNumber *pn,
	bool keep_raw = false)
{
	const std::string n = to_string(number);
	const std::string r = to_region(region);
	PhoneNumberUtil::ErrorType err = keep_raw ?
		util->ParseAndKeepRawInput(n, r, pn) : util->Parse(n, r, pn);
	return err == PhoneNumberUtil::NO_PARSING_ERROR ? PN_OK : PN_ERR_PARSE;
}

/* every entry point goes through this, so that no C++ exception can ever
 * unwind into the C code */
template <typename F>
int guard(F f) noexcept
{
	if (!util)
		return PN_ERR_INTERNAL;
	try {
		return f();
	} catch (...) {
		return PN_ERR_INTERNAL;
	}
}

inline int to_bool(bool b)
{
	return b ? PN_OK : PN_FALSE;
}

inline bool valid_type(int t)
{
	return t >= PN_TYPE_FIXED_LINE && t <= PN_TYPE_UNKNOWN;
}

} /* namespace */

extern "C" {

int pn_init(pn_log_f log_func)
{
	try {
		PhoneNumberUtil *u = PhoneNumberUtil::GetInstance();
		if (!u)
			return PN_ERR_INTERNAL;
		/* PhoneNumberUtil takes ownership of the logger */
		OpenSIPSLogger *logger = new OpenSIPSLogger(log_func);
		logger->set_level(i18n::phonenumbers::LOG_WARNING);
		u->SetLogger(logger);
		util = u;

		static ShortNumberInfo sni;
		short_info = &sni;
	} catch (...) {
		return PN_ERR_INTERNAL;
	}
	return PN_OK;
}

int pn_convert_alpha_characters(const pn_str *number, pn_str *out)
{
	return guard([&] {
		result = to_string(number);
		util->ConvertAlphaCharactersInNumber(&result);
		return set_result(out);
	});
}

int pn_normalize_digits_only(const pn_str *number, pn_str *out)
{
	return guard([&] {
		result = to_string(number);
		util->NormalizeDigitsOnly(&result);
		return set_result(out);
	});
}

int pn_normalize_diallable_chars_only(const pn_str *number, pn_str *out)
{
	return guard([&] {
		result = to_string(number);
		util->NormalizeDiallableCharsOnly(&result);
		return set_result(out);
	});
}

int pn_is_alpha_number(const pn_str *number)
{
	return guard([&] {
		return to_bool(util->IsAlphaNumber(to_string(number)));
	});
}

int pn_format(const pn_str *number, const pn_str *region,
	enum pn_format fmt, pn_str *out)
{
	return guard([&] {
		if (fmt < PN_FMT_E164 || fmt > PN_FMT_RFC3966)
			return PN_ERR_ARG;
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->Format(pn, static_cast<PhoneNumberUtil::PhoneNumberFormat>(fmt),
			&result);
		return set_result(out);
	});
}

int pn_format_in_original_format(const pn_str *number, const pn_str *region,
	const pn_str *calling_from, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn, true) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->FormatInOriginalFormat(pn, to_region(calling_from), &result);
		return set_result(out);
	});
}

int pn_format_national_with_carrier_code(const pn_str *number,
	const pn_str *region, const pn_str *carrier_code, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->FormatNationalNumberWithCarrierCode(pn, to_string(carrier_code),
			&result);
		return set_result(out);
	});
}

int pn_format_national_with_preferred_carrier_code(const pn_str *number,
	const pn_str *region, const pn_str *fallback_carrier_code, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn, true) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->FormatNationalNumberWithPreferredCarrierCode(pn,
			to_string(fallback_carrier_code), &result);
		return set_result(out);
	});
}

int pn_format_for_mobile_dialing(const pn_str *number, const pn_str *region,
	const pn_str *calling_from, int with_formatting, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->FormatNumberForMobileDialing(pn, to_region(calling_from),
			with_formatting != 0, &result);
		return set_result(out);
	});
}

int pn_format_out_of_country(const pn_str *number, const pn_str *region,
	const pn_str *calling_from, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->FormatOutOfCountryCallingNumber(pn, to_region(calling_from),
			&result);
		return set_result(out);
	});
}

int pn_format_out_of_country_keeping_alpha(const pn_str *number,
	const pn_str *region, const pn_str *calling_from, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn, true) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->FormatOutOfCountryKeepingAlphaChars(pn, to_region(calling_from),
			&result);
		return set_result(out);
	});
}

int pn_truncate_too_long_number(const pn_str *number, const pn_str *region,
	pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		if (!util->TruncateTooLongNumber(&pn))
			return PN_FALSE;
		result.clear();
		util->Format(pn, PhoneNumberUtil::E164, &result);
		return set_result(out);
	});
}

int pn_get_country_code(const pn_str *number, const pn_str *region, int *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		*out = pn.country_code();
		return *out > 0 ? PN_OK : PN_FALSE;
	});
}

int pn_get_national_significant_number(const pn_str *number,
	const pn_str *region, pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->GetNationalSignificantNumber(pn, &result);
		return set_result(out);
	});
}

int pn_get_length_of_geographical_area_code(const pn_str *number,
	const pn_str *region, int *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		*out = util->GetLengthOfGeographicalAreaCode(pn);
		return *out > 0 ? PN_OK : PN_FALSE;
	});
}

int pn_get_length_of_national_destination_code(const pn_str *number,
	const pn_str *region, int *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		*out = util->GetLengthOfNationalDestinationCode(pn);
		return *out > 0 ? PN_OK : PN_FALSE;
	});
}

int pn_get_number_type(const pn_str *number, const pn_str *region,
	enum pn_type *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		*out = static_cast<enum pn_type>(util->GetNumberType(pn));
		return PN_OK;
	});
}

int pn_get_region_code_for_number(const pn_str *number, const pn_str *region,
	pn_str *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		result.clear();
		util->GetRegionCodeForNumber(pn, &result);
		if (result == PN_UNKNOWN_REGION)
			result.clear();
		return set_result(out);
	});
}

int pn_is_valid_number(const pn_str *number, const pn_str *region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(util->IsValidNumber(pn));
	});
}

int pn_is_valid_number_for_region(const pn_str *number, const pn_str *region,
	const pn_str *for_region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(util->IsValidNumberForRegion(pn, to_region(for_region)));
	});
}

int pn_is_possible_number(const pn_str *number, const pn_str *region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(util->IsPossibleNumber(pn));
	});
}

int pn_is_possible_number_with_reason(const pn_str *number,
	const pn_str *region, enum pn_validation *out)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		*out = static_cast<enum pn_validation>(
			util->IsPossibleNumberWithReason(pn));
		return (*out == PN_VAL_IS_POSSIBLE ||
			*out == PN_VAL_IS_POSSIBLE_LOCAL_ONLY) ? PN_OK : PN_FALSE;
	});
}

int pn_is_possible_number_for_type(const pn_str *number, const pn_str *region,
	enum pn_type type)
{
	return guard([&] {
		if (!valid_type(type))
			return PN_ERR_ARG;
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(util->IsPossibleNumberForType(pn,
			static_cast<PhoneNumberUtil::PhoneNumberType>(type)));
	});
}

int pn_is_possible_number_for_string(const pn_str *number,
	const pn_str *dialing_from)
{
	return guard([&] {
		return to_bool(util->IsPossibleNumberForString(to_string(number),
			to_region(dialing_from)));
	});
}

int pn_can_be_internationally_dialled(const pn_str *number,
	const pn_str *region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(util->CanBeInternationallyDialled(pn));
	});
}

int pn_is_number_geographical(const pn_str *number, const pn_str *region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(util->IsNumberGeographical(pn));
	});
}

int pn_is_number_match(const pn_str *number1, const pn_str *region1,
	const pn_str *number2, const pn_str *region2, enum pn_match *out)
{
	return guard([&] {
		/* a number that cannot be parsed for its region (typically a
		 * national number with an unknown region) is still compared by
		 * its national significant number, which may yield NSN_MATCH */
		PhoneNumber pn1, pn2;
		const bool ok1 = parse(number1, region1, &pn1) == PN_OK;
		const bool ok2 = parse(number2, region2, &pn2) == PN_OK;
		PhoneNumberUtil::MatchType m;
		if (ok1 && ok2)
			m = util->IsNumberMatch(pn1, pn2);
		else if (ok1)
			m = util->IsNumberMatchWithOneString(pn1, to_string(number2));
		else if (ok2)
			m = util->IsNumberMatchWithOneString(pn2, to_string(number1));
		else
			m = util->IsNumberMatchWithTwoStrings(to_string(number1),
				to_string(number2));
		*out = static_cast<enum pn_match>(m);
		switch (*out) {
		case PN_MATCH_INVALID_NUMBER:
			return PN_ERR_PARSE;
		case PN_MATCH_NO_MATCH:
			return PN_FALSE;
		default:
			return PN_OK;
		}
	});
}

int pn_get_country_code_for_region(const pn_str *region, int *out)
{
	return guard([&] {
		*out = util->GetCountryCodeForRegion(to_region(region));
		return *out > 0 ? PN_OK : PN_ERR_ARG;
	});
}

int pn_get_region_code_for_country_code(int country_code, pn_str *out)
{
	return guard([&] {
		result.clear();
		util->GetRegionCodeForCountryCode(country_code, &result);
		if (result == PN_UNKNOWN_REGION)
			return PN_ERR_ARG;
		return set_result(out);
	});
}

int pn_get_region_codes_for_country_code(int country_code, pn_str *out)
{
	return guard([&] {
		std::list<std::string> regions;
		util->GetRegionCodesForCountryCallingCode(country_code, &regions);
		if (regions.empty())
			return PN_ERR_ARG;
		result.clear();
		for (const auto &r : regions) {
			if (!result.empty())
				result += ',';
			result += r;
		}
		return set_result(out);
	});
}

int pn_get_country_mobile_token(int country_code, pn_str *out)
{
	return guard([&] {
		result.clear();
		util->GetCountryMobileToken(country_code, &result);
		return set_result(out);
	});
}

int pn_get_ndd_prefix_for_region(const pn_str *region, int strip_non_digits,
	pn_str *out)
{
	return guard([&] {
		result.clear();
		util->GetNddPrefixForRegion(to_region(region), strip_non_digits != 0,
			&result);
		return set_result(out);
	});
}

int pn_is_nanpa_country(const pn_str *region)
{
	return guard([&] {
		return to_bool(util->IsNANPACountry(to_region(region)));
	});
}

int pn_get_example_number(const pn_str *region, int use_type,
	enum pn_type type, pn_str *out)
{
	return guard([&] {
		if (use_type && !valid_type(type))
			return PN_ERR_ARG;
		PhoneNumber pn;
		const std::string r = to_region(region);
		bool found = use_type ?
			util->GetExampleNumberForType(r,
				static_cast<PhoneNumberUtil::PhoneNumberType>(type), &pn) :
			util->GetExampleNumber(r, &pn);
		if (!found)
			return PN_FALSE;
		result.clear();
		util->Format(pn, PhoneNumberUtil::E164, &result);
		return set_result(out);
	});
}

/*
 * Short numbers are always national, so they are parsed against a real
 * region and only matched for that same region.
 */
int pn_is_emergency_number(const pn_str *number, const pn_str *region)
{
	return guard([&] {
		return to_bool(short_info->IsEmergencyNumber(to_string(number),
			to_region(region)));
	});
}

int pn_connects_to_emergency_number(const pn_str *number,
	const pn_str *region)
{
	return guard([&] {
		return to_bool(short_info->ConnectsToEmergencyNumber(
			to_string(number), to_region(region)));
	});
}

int pn_is_valid_short_number(const pn_str *number, const pn_str *region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(short_info->IsValidShortNumberForRegion(pn,
			to_region(region)));
	});
}

int pn_is_possible_short_number(const pn_str *number, const pn_str *region)
{
	return guard([&] {
		PhoneNumber pn;
		if (parse(number, region, &pn) != PN_OK)
			return PN_ERR_PARSE;
		return to_bool(short_info->IsPossibleShortNumberForRegion(pn,
			to_region(region)));
	});
}

} /* extern "C" */
