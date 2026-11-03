#!/bin/sh
#
# Runs the functional test bundle (test/run-tests.sh) of every built
# community-contributed module. Must be run from the source tree root, after
# scripts/build/do_build.sh. Modules which were not built (e.g. excluded) are
# skipped.

set -e

failed=""
for runner in modules-contrib/*/test/run-tests.sh
do
	[ -f "${runner}" ] || continue
	mod_dir=$(dirname "$(dirname "${runner}")")
	mod=$(basename "${mod_dir}")

	if [ ! -f "${mod_dir}/${mod}.so" ]
	then
		echo "Skipping ${mod}: ${mod_dir}/${mod}.so was not built"
		continue
	fi

	echo "Running the ${mod} contrib module tests"
	if ! bash "${runner}"
	then
		failed="${failed} ${mod}"
	fi
done

if [ -n "${failed}" ]
then
	echo "Contrib module tests failed:${failed}" >&2
	exit 1
fi
