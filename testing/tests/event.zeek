# @TEST-DOC: Test for exporting types.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/export_test.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

event Export_Test::seen_a(c: connection, is_orig: bool, a: Export_Test::A)
    {
    print fmt("Testing: %s", a);
    }
