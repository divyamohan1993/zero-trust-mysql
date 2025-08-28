package mysql.hardening

deny[msg] {
  input.require_secure_transport != "ON"
  msg := "require_secure_transport must be ON"
}

deny[msg] {
  input.local_infile != "OFF"
  msg := "local_infile must be OFF"
}

deny[msg] {
  input.skip_name_resolve != "ON"
  msg := "skip_name_resolve must be ON"
}

deny[msg] {
  not contains(input.sql_mode, "STRICT_ALL_TABLES")
  msg := "sql_mode must include STRICT_ALL_TABLES"
}

contains(str, substr) {
  indexof(str, substr) >= 0
}