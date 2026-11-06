# Script tests

Black-box tests that run a real `opensips` binary (a normal build, not the
`-DUNIT_TESTS` one used by `make test`). CI runs them via
`.github/workflows/script-tests.yml`.

Run locally after building (`make opensips`):

    sh test/script/run_all.sh ./opensips     # everything
    sh test/script/xlog-format/run.sh ./opensips   # one feature

## Adding a test

1. Create `test/script/<feature>/run.sh` (it is picked up automatically by
   `run_all.sh` and CI - nothing to register).
2. Start it with:

       . "$(dirname "$0")/../lib.sh"
       script_init "$@"

   and end it with `finish`. See `lib.sh` for the helpers:

   - `check_parse accept|reject "<description>" '<config body>'` - config
     parse check (`opensips -c`); the body is prefixed with `$CFG_PRELUDE`.
   - `check_parse_file accept|reject "<description>" <file>` - same, for a
     config file.
   - `run_for <seconds> <cfg> <out>` - run opensips briefly (use
     `startup_route` to produce output) and capture stdout/stderr to check
     with `grep`.
   - `result "<description>" $?` - record any other check.

3. Put any config files your runtime checks need next to `run.sh`.

`xlog-format/` is a worked example of both a parse and a runtime test.
