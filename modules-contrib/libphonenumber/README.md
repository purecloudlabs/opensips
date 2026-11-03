---
title: "libphonenumber Module"
description: "This module parses, formats and validates international phone numbers using Google's libphonenumber library."
---

## Admin Guide


### Overview


The *libphonenumber* module exposes Google's
[libphonenumber](https://github.com/google/libphonenumber) library to the
OpenSIPS script. It can parse, normalize, format and validate phone numbers
of any country, classify them (mobile, fixed line, toll free, ...), look up
the regions behind a country calling code and recognize emergency and other
short numbers.


Typical uses are normalizing the R-URI or the caller ID to E.164 before
routing or a database lookup, rejecting impossible numbers early, or
re-formatting a number as it must be dialed from the callee's country.


This is a *contributed module*: it lives under
`modules-contrib/`, it is not maintained by the OpenSIPS core
team and it is not built by default.


### Regions


Most functions accept an optional *region* parameter: the
two letter ISO 3166-1 region code (case insensitive) the number is dialed
from. It is only used to parse numbers written in national format (e.g.
"020 7031 3000" for "GB"); numbers in international format ("+44 20 7031
3000") are parsed regardless of it.


When the *region* parameter is missing or empty, the
[default_region](#default_region-string) module parameter is used. The
special region "ZZ" stands for "unknown region", in which case only
numbers in international format can be parsed.


### Return Codes


All the functions follow the same convention:


- *1* - success / true. If the function has
an output variable, it was set.
- *-1* - false (the number is not valid,
not possible, does not match, ...) or there is no value to return (e.g. a
region without a national dialing prefix). Unless documented otherwise, the
output variable is left untouched.
- *-2* - the phone number could not be
parsed.
- *-3* - invalid argument (unknown region,
country calling code, format or number type).
- *-4* - internal error.


Since every negative value evaluates to false, the functions can be used
directly in *if* statements, while *$rc*
tells the reason of a failure:


```opensips title="Checking the return code"
...
if (!pn_format($rU, "E164", $var(e164), "US")) {
	if ($rc == -2)
		send_reply(484, "Address Incomplete");
	else
		send_reply(500, "Server Internal Error");
	exit;
}
$rU = $var(e164);
...
```


### Number Formats


The formats accepted by
[pn_format()](#pn_formatnumber-format-out_var-region) (case insensitive;
the numeric value is also accepted):


- *E164* (0) - "+16502530000"
- *INTERNATIONAL* (1) - "+1 650-253-0000"
- *NATIONAL* (2) - "(650) 253-0000"
- *RFC3966* (3) - "tel:+1-650-253-0000"


### Number Types


The number types returned by
[pn_get_number_type()](#pn_get_number_typenumber-out_var-region) and
accepted by the functions taking a *type* parameter (case
insensitive; the numeric value is also accepted):
*FIXED_LINE* (0), *MOBILE* (1),
*FIXED_LINE_OR_MOBILE* (2), *TOLL_FREE*
(3), *PREMIUM_RATE* (4), *SHARED_COST*
(5), *VOIP* (6), *PERSONAL_NUMBER* (7),
*PAGER* (8), *UAN* (9),
*VOICEMAIL* (10), *UNKNOWN* (11).


### Dependencies


#### OpenSIPS Modules


This module does not depend on other modules.


#### External Libraries or Applications


The module bundles Google's libphonenumber (v9.0.42) and the abseil version it
requires as git submodules under *lib/*; they are built
automatically and linked statically into the module, so no libphonenumber
installation is needed. The build requires:


- a C++17 compiler (g++ or clang++, matching the C compiler in use);
- *cmake* (3.16 or newer) and *pkg-config*;
- *protobuf* - library and compiler
(*libprotobuf-dev* and *protobuf-compiler* on
Debian / Ubuntu, *protobuf-devel* and
*protobuf-compiler* on Fedora / RHEL);
- *ICU* (*libicu-dev* /
*libicu-devel*).


At runtime the module only needs the protobuf and ICU shared libraries.


### Compilation


Make sure the submodules are checked out (a recursive clone, or):


```bash
git submodule update --init --recursive
```


Being a contributed module, it is built along with the other contributed
modules, or explicitly:


```bash title="Building and installing the module"
make modules-contrib
make modules=modules-contrib/libphonenumber modules-contrib
make modules=modules-contrib/libphonenumber install-modules-all
```


The phone number metadata comes with the bundled library: updating the
*lib/libphonenumber* submodule to a newer libphonenumber release
is the way to pick up numbering plan changes.


To link against a libphonenumber installed on the system instead (version 8.12
or newer, e.g. *libphonenumber-dev*), set
*LPN_USE_SYSTEM=yes*, optionally along with
*LPN_PREFIX* for a non standard installation prefix (defaults to
*LOCALBASE*):


```bash
make modules=modules-contrib/libphonenumber modules-contrib LPN_USE_SYSTEM=yes
make modules=modules-contrib/libphonenumber modules-contrib LPN_USE_SYSTEM=yes LPN_PREFIX=/opt/libphonenumber
```


### Exported Parameters


#### default_region (string)


The region used to parse numbers in national format when a function is
called without a *region* parameter. It must be a region known
by libphonenumber, or "ZZ" (only numbers in international format are
accepted). OpenSIPS refuses to start if the region is unknown.


*Default value is "ZZ".*


```opensips title="Setting the default_region parameter"
...
modparam("libphonenumber", "default_region", "US")
...
```


### Exported Functions


All the functions can be used from any route. All the string parameters
accept variables and formatted strings.


#### pn_format(number, format, out_var, [region])


Formats a phone number in the given format, see [Number Formats](#number-formats).


- *number* (string) - the phone number.
- *format* (string) - the output format.
- *out_var* (var) - receives the formatted number.
- *region* (string, optional) - the region to parse the number for.


```opensips title="pn_format usage"
...
# "(650) 253-0000" -> "+16502530000"
pn_format($fU, "E164", $var(caller), "US");
...
```


#### pn_format_in_original_format(number, calling_from, out_var, [region])


Formats a phone number keeping the format it was entered in (with or without
the national prefix, international dialing prefix, ...), as dialed from the
*calling_from* region.


```opensips title="pn_format_in_original_format usage"
...
# "011 44 20 7031 3000" stays "011 44 20 7031 3000"
pn_format_in_original_format("011 44 20 7031 3000", "US", $var(out), "US");
...
```


#### pn_format_national_number_with_carrier_code(number, carrier_code, out_var, [region])


Formats a number in national format, inserting the given carrier selection
code (only applies to regions using carrier codes, e.g. Brazil, Argentina).


```opensips title="pn_format_national_number_with_carrier_code usage"
...
# "0 15 (11) 2345-6789"
pn_format_national_number_with_carrier_code("011 2345 6789", "15", $var(out), "BR");
...
```


#### pn_format_national_number_with_preferred_carrier_code(number, fallback_carrier_code, out_var, [region])


Same as above, but the carrier code found in the number itself, if any, takes
precedence over *fallback_carrier_code*.


#### pn_format_number_for_mobile_dialing(number, calling_from, with_formatting, out_var, [region])


Formats the number as it should be dialed from a mobile phone in the
*calling_from* region. *with_formatting* (int)
selects whether the result keeps formatting symbols (spaces, dashes). Returns
*-1* if the number cannot be dialed from that region.


#### pn_format_out_of_country_calling_number(number, calling_from, out_var, [region])


Formats the number as it must be dialed from the
*calling_from* region, using that region's international
dialing prefix (e.g. "00 1 650-253-0000" from "DE", "1 (650) 253-0000" from
another NANPA region).


#### pn_format_out_of_country_keeping_alpha_chars(number, calling_from, out_var, [region])


Same as above, but keeps the letters of vanity numbers (e.g. "0011 1 800
SIX-FLAG" from "AU").


#### pn_truncate_too_long_number(number, out_var, [region])


Removes trailing digits from a too long number until it becomes valid and
returns it in E.164 format. Returns *-1* if no valid number
can be obtained.


#### pn_convert_alpha_characters_in_number(number, out_var)


Converts the letters of a vanity number to digits, keeping all the other
characters ("1-800-FLOWERS" becomes "1-800-3569377").


#### pn_normalize_digits_only(number, out_var)


Keeps only the digits of the number (any Unicode digit is converted to ASCII).
Returns *-1* if the number has no digits.


#### pn_normalize_diallable_chars_only(number, out_var)


Keeps only the diallable characters of the number (digits, "+", "*" and "#").
Returns *-1* if nothing is left.


#### pn_is_alpha_number(number)


Returns *1* if the number is a valid vanity number (contains
letters), e.g. "1800 six-flags".


#### pn_get_country_code(number, out_var, [region])


Returns, as integer, the country calling code of the number (e.g. 44).


#### pn_get_national_significant_number(number, out_var, [region])


Returns the national significant number (the number without country calling
code and national prefix, but with Italian leading zeros), e.g. "2070313000"
for "+44 20 7031 3000".


#### pn_get_length_of_geographical_area_code(number, out_var, [region])


Returns, as integer, the length of the geographical area code of the number.
Returns *-1* if the number has no geographical area code (e.g.
mobile or toll free numbers in many regions).


#### pn_get_length_of_national_destination_code(number, out_var, [region])


Returns, as integer, the length of the national destination code (area code
or mobile network code). Returns *-1* if there is none.


#### pn_get_number_type(number, out_var, [region])


Returns the type of the number as a string, see [Number Types](#number-types).
Numbers which are not valid get the *UNKNOWN* type.


```opensips title="pn_get_number_type usage"
...
if (pn_get_number_type($rU, $var(type), "GB") && $var(type) == "PREMIUM_RATE") {
	send_reply(403, "Premium Rate Numbers Not Allowed");
	exit;
}
...
```


#### pn_get_region_code_for_number(number, out_var, [region])


Returns the region the number belongs to (e.g. "CA" for "+1 204 234 5678", or
"001" for non geographical numbers such as "+800 1234 5678"). Returns
*-1* if the number does not belong to any region.


#### pn_is_valid_number(number, [region])


Returns *1* if the number is a valid number (it matches the
numbering plan of its region).


#### pn_is_valid_number_for_region(number, for_region, [region])


Returns *1* if the number is a valid number of the
*for_region* region (*region* is still the
one used to parse the number).


#### pn_is_possible_number(number, [region])


Returns *1* if the length of the number is possible for its
region (a faster, less strict check than validation). Local only numbers
(without area code) are considered possible.


#### pn_is_possible_number_with_reason(number, out_var, [region])


Same as above, but *out_var* also receives the reason, even
when the function returns *-1*: *IS_POSSIBLE*,
*IS_POSSIBLE_LOCAL_ONLY*,
*INVALID_COUNTRY_CODE*, *TOO_SHORT*,
*INVALID_LENGTH* or *TOO_LONG*.


#### pn_is_possible_number_for_type(number, type, [region])


Returns *1* if the length of the number is possible for the
given number type of its region.


#### pn_is_possible_number_for_string(number, dialing_from)


Same as pn_is_possible_number(), for a number dialed from the
*dialing_from* region; also returns *-1* if
the number cannot be parsed at all.


#### pn_can_be_internationally_dialled(number, [region])


Returns *1* if the number can be dialed from outside its
region (some national services, e.g. "0810" numbers in Argentina, cannot).


#### pn_is_number_geographical(number, [region])


Returns *1* if the number is associated with a geographical
area (fixed line, or mobile in regions where mobile numbers are
geographical).


#### pn_is_number_match(number1, number2, [region1], [region2], [match_var])


Compares two phone numbers. Returns *1* if they match
(*EXACT_MATCH*, *NSN_MATCH* or
*SHORT_NSN_MATCH*), *-1* if they do not
(*NO_MATCH*) and *-2* if any of them is
not a number (*INVALID_NUMBER*). The kind of match is stored
in *match_var*, if given, even on failure.


A number that cannot be parsed for its region (typically a national number
with region "ZZ") is compared by its national significant number only, which
gives a *NSN_MATCH* when the digits are the same.


```opensips title="pn_is_number_match usage"
...
if (pn_is_number_match($fU, $var(allowed_caller), , , $var(match)) &&
		$var(match) == "EXACT_MATCH")
	xlog("caller is allowed\n");
...
```


#### pn_get_country_code_for_region(region, out_var)


Returns, as integer, the country calling code of a region (e.g. 36 for
"HU"). Returns *-3* for unknown regions.


#### pn_get_region_code_for_country_code(country_code, out_var)


Returns the main region of a country calling code (e.g. "US" for 1, "001" for
non geographical codes such as 800). Returns *-3* for unknown
codes.


#### pn_get_region_codes_for_country_code(country_code, out_var)


Returns the comma separated list of all the regions sharing a country calling
code, main region first (e.g. "RU,KZ" for 7).


#### pn_get_country_mobile_token(country_code, out_var)


Returns the mobile token of the country calling code, which must be inserted
before the area code of mobile numbers when dialed from abroad (e.g. "9" for
Argentina). Returns *-1* if the country has none.


#### pn_get_ndd_prefix_for_region(region, strip_non_digits, out_var)


Returns the national direct dialing prefix of a region (e.g. "06" for "HU").
If *strip_non_digits* (int) is non zero, any non digit
character is removed from it. Returns *-1* if the region has
no prefix or is unknown.


#### pn_is_nanpa_country(region)


Returns *1* if the region is part of the North American
Numbering Plan (country calling code 1).


#### pn_get_example_number(region, out_var, [type])


Returns, in E.164 format, an example number of the region, optionally of the
given type (see [Number Types](#number-types)). Returns *-1* if
there is no such example. Mostly useful for testing.


#### pn_is_emergency_number(number, [region])


Returns *1* if the number is exactly an emergency number of
the region (e.g. "911" for "US", "112" or "999" for "GB").


```opensips title="pn_is_emergency_number usage"
...
if (pn_is_emergency_number($rU, $var(caller_region))) {
	route(EMERGENCY);
	exit;
}
...
```


#### pn_connects_to_emergency_number(number, [region])


Returns *1* if dialing the number would connect to an
emergency service of the region, including numbers that merely start with an
emergency number (e.g. "9116666666" in "US"); in regions where emergency
numbers must be dialed exactly (e.g. Brazil, Chile) the match is exact.


#### pn_is_valid_short_number(number, [region])


Returns *1* if the number is a valid short number (emergency,
service code, ...) of the region.


#### pn_is_possible_short_number(number, [region])


Returns *1* if the length of the number is possible for a
short number of the region.


### Testing


The module ships a functional test bundle that calls every exported function
with valid, invalid and edge case inputs and checks both the return code and
the output, along with a few configuration error checks. The CI runs it
(through *scripts/build/run_contrib_tests.sh*) after every build;
to run it by hand, from the source tree root:


```bash
make opensips
make modules=modules-contrib/libphonenumber modules-contrib
modules-contrib/libphonenumber/test/run-tests.sh
```


Use the *OPENSIPS* and *MPATH* environment
variables to test an installed OpenSIPS and module instead. The expected values
come from the libphonenumber metadata and may need adjusting if a future
numbering plan update changes them.


### Upgrading from older versions


Compared to the earlier, out of tree version of this module:


- the module is named *libphonenumber* (it used to report
itself as "phonenumer");
- the *format* parameter of
pn_format() is a format name ("E164", "INTERNATIONAL", ...); numeric values
must now be passed as strings ("0" .. "3");
- pn_get_number_type() returns the type name (e.g.
"MOBILE") instead of an integer;
- pn_is_number_match() returns *1* for any
kind of match and *-1* for no match (it used to return the
match type, so *NO_MATCH* evaluated to true); the match type
is available through the new *match_var* parameter;
- the default region is configurable with the
[default_region](#default_region-string) parameter;
- strings are no longer truncated to 32 characters, and region codes are
case insensitive;
- new functions: pn_get_country_code(), pn_truncate_too_long_number(),
pn_is_possible_number_with_reason(), pn_is_possible_number_for_type(),
pn_can_be_internationally_dialled(), pn_is_number_geographical(),
pn_get_region_codes_for_country_code(), pn_get_example_number(),
pn_is_emergency_number(), pn_connects_to_emergency_number(),
pn_is_valid_short_number() and pn_is_possible_short_number().
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
