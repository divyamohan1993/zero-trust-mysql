#!/usr/bin/env python3
import sys,hashlib,binascii,json
import mysql.connector
conn=mysql.connector.connect(host="127.0.0.1",user="auditor",password="Audit#ChangeMe!23",database="securedb",ssl_disabled=False)
cur=conn.cursor(dictionary=True)
cur.execute("SELECT id,HEX(prev_hash) ph,HEX(curr_hash) ch, table_name, action FROM audit_events ORDER BY id")
prev=None
ok=True
for r in cur:
if prev and prev!=r["ph"]:
ok=False; print("BREAK at",r["id"]); break
prev=r["ch"]
print("OK" if ok else "FAIL")