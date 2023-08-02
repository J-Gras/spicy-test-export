spicy_add_analyzer(
    NAME Export_Test
    PACKAGE_NAME zeek-export_test
    SOURCES export_test.spicy export_test.evt zeek_export_test.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
