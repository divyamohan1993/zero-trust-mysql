.PHONY: evidence openscap policy

evidence:
	./scripts/collect_mysql_vars.sh

openscap:
	./scripts/openscap_scan.sh

policy: evidence
	conftest test --policy policy evidence/mysql_vars.json