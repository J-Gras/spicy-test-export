# @TEST-DOC: Test for logging of exported types.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/export_test.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff export_test.log

redef record Export_Test::A$b1 += { &log };
redef record Export_Test::A$b2 += { &log };
redef record Export_Test::A$b3 += { &log };
redef record Export_Test::A$b4 += { &log };
