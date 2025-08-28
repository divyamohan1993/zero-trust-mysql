#!/usr/bin/env bash

# (D) VM one-click deployer

set -euo pipefail
ALLOW_REMOTE="${ALLOW_REMOTE:-0}"
ALLOWED_CIDR="${ALLOWED_CIDR:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
DB_NAME="securedb"
OS="$(. /etc/os-release; echo "${ID:-unknown}")"
CFG="/etc/mysql/mysql.conf.d/mysqld.cnf"
ROOT_MYSQL="sudo mysql -uroot"
PKI_TAR="${PKI_TAR:-/tmp/pki_server.tar.gz}"

trap 'systemctl is-active mysql >/dev/null 2>&1 || sudo systemctl restart mysql || true; exit 1' ERR

if [[ "$OS" = "ubuntu" || "$OS" = "debian" ]]; then
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y ufw jq python3 python3-pip unattended-upgrades fail2ban google-cloud-ops-agent openscap-scanner scap-security-guide mysql-client
elif [[ "$OS" = "centos" || "$OS" = "rhel" || "$OS" = "rocky" || "$OS" = "almalinux" ]]; then
  yum install -y epel-release || true
  yum install -y ufw jq python3 python3-pip fail2ban openscap-scanner scap-security-guide mysql || true
  curl -sS https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh | bash
  yum install -y google-cloud-ops-agent || true
fi
systemctl enable --now google-cloud-ops-agent || true
mkdir -p /opt/pki/server
if [[ -f "$PKI_TAR" ]]; then tar -C /opt/pki/server -xzf "$PKI_TAR"; fi
test -s /opt/pki/server/server-cert.pem
test -s /opt/pki/server/server-key.pem
test -s /opt/pki/server/ca-cert.pem
chown -R mysql:mysql /opt/pki/server
chmod 600 /opt/pki/server/server-key.pem
mkdir -p /var/lib/mysql-files
chown mysql:mysql /var/lib/mysql-files

if [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]]; then CFG=/etc/mysql/mysql.conf.d/mysqld.cnf; elif [[ -f /etc/my.cnf ]]; then CFG=/etc/my.cnf; fi
cp -a "$CFG" "${CFG}.bak.$(date +%s)" || true

cat >"$CFG" <<EOF
[mysqld]
require_secure_transport=ON
ssl_cert=/opt/pki/server/server-cert.pem
ssl_key=/opt/pki/server/server-key.pem
ssl_ca=/opt/pki/server/ca-cert.pem
ssl_cipher=TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
local_infile=0
secure_file_priv=/var/lib/mysql-files
skip_symbolic_links=1
skip_name_resolve=ON
sql_mode=STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
max_connections=200
event_scheduler=ON
bind-address=127.0.0.1
EOF
if [[ "$ALLOW_REMOTE" = "1" ]]; then sed -i 's/^bind-address=.*/bind-address=0.0.0.0/' "$CFG"; fi
systemctl restart mysql

$ROOT_MYSQL -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
for U in db_owner app_user app_api auditor migration api_definer; do $ROOT_MYSQL -e "DROP USER IF EXISTS '${U}'@'localhost';"; done
$ROOT_MYSQL -e "CREATE USER 'db_owner'@'localhost' IDENTIFIED BY 'Owner#ChangeMe!23' REQUIRE X509;"
$ROOT_MYSQL -e "CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'App#ChangeMe!23' REQUIRE X509;"
$ROOT_MYSQL -e "CREATE USER 'app_api'@'localhost' IDENTIFIED BY 'NoLogin#Blocked!23' ACCOUNT LOCK;"
$ROOT_MYSQL -e "CREATE USER 'auditor'@'localhost' IDENTIFIED BY 'Audit#ChangeMe!23' REQUIRE X509;"
$ROOT_MYSQL -e "CREATE USER 'migration'@'localhost' IDENTIFIED BY 'Migrate#ChangeMe!23' REQUIRE X509;"
$ROOT_MYSQL -e "CREATE USER 'api_definer'@'localhost' IDENTIFIED BY 'Def#$(head -c16 /dev/urandom | xxd -p)' ACCOUNT LOCK PASSWORD EXPIRE NEVER;"
$ROOT_MYSQL -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO 'db_owner'@'localhost'; FLUSH PRIVILEGES;"

SQL=$(cat <<'SQL_EOF'
USE securedb;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS session_ctx;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

CREATE TABLE tenants(id BINARY(16) PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID(),1)),name VARCHAR(255) NOT NULL UNIQUE) ENGINE=InnoDB;

CREATE TABLE users(
  id BINARY(16) PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID(),1)),
  tenant_id BINARY(16) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  role ENUM('admin','manager','analyst','viewer') NOT NULL,
  pii_wrapped_key VARBINARY(2048) NOT NULL,
  pii_pq_wrapped_key VARBINARY(4096) NOT NULL,
  pq_alg VARCHAR(32) NOT NULL,
  kms_key_name VARCHAR(256) NOT NULL,
  email_ct VARBINARY(8192) NOT NULL,
  email_iv VARBINARY(16) NOT NULL,
  email_aad VARBINARY(64) NULL,
  phone_ct VARBINARY(8192) NOT NULL,
  phone_iv VARBINARY(16) NOT NULL,
  phone_aad VARBINARY(64) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE accounts(
  id BINARY(16) PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID(),1)),
  tenant_id BINARY(16) NOT NULL,
  owner_user BINARY(16) NOT NULL,
  balance_cents BIGINT NOT NULL CHECK (balance_cents>=0),
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_accts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT fk_accts_owner FOREIGN KEY (owner_user) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE session_ctx(conn_id INT PRIMARY KEY,tenant_id BINARY(16) NULL,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB;

CREATE TABLE audit_events(
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  ts TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  actor VARCHAR(128) NOT NULL,
  app_tenant CHAR(36) NULL,
  table_name VARCHAR(64) NOT NULL,
  action ENUM('INSERT','UPDATE','DELETE') NOT NULL,
  pk_text VARCHAR(64) NULL,
  before_doc JSON NULL,
  after_doc JSON NULL,
  client_addr VARCHAR(64) NULL,
  prev_hash VARBINARY(32) NULL,
  curr_hash VARBINARY(32) NULL
) ENGINE=InnoDB;

DELIMITER $$
CREATE DEFINER='api_definer'@'localhost' PROCEDURE security_set_tenant(p_tenant CHAR(36)) SQL SECURITY DEFINER BEGIN INSERT INTO session_ctx(conn_id,tenant_id) VALUES(CONNECTION_ID(),UUID_TO_BIN(p_tenant,1)) ON DUPLICATE KEY UPDATE tenant_id=VALUES(tenant_id); END$$
CREATE DEFINER='api_definer'@'localhost' FUNCTION get_tenant() RETURNS BINARY(16) SQL SECURITY DEFINER BEGIN DECLARE t BINARY(16); SELECT tenant_id INTO t FROM session_ctx WHERE conn_id=CONNECTION_ID(); RETURN t; END$$

CREATE DEFINER='api_definer'@'localhost' PROCEDURE app_create_user_encrypted(
  IN p_tenant CHAR(36), IN p_name VARCHAR(255), IN p_role VARCHAR(16),
  IN p_wrapped_key VARBINARY(2048), IN p_pq_wrapped VARBINARY(4096), IN p_pq_alg VARCHAR(32), IN p_kms_key_name VARCHAR(256),
  IN p_email_ct VARBINARY(8192), IN p_email_iv VARBINARY(16), IN p_email_aad VARBINARY(64),
  IN p_phone_ct VARBINARY(8192), IN p_phone_iv VARBINARY(16), IN p_phone_aad VARBINARY(64),
  OUT o_user_id CHAR(36)
) SQL SECURITY DEFINER
BEGIN
  DECLARE v_tid BINARY(16); DECLARE v_uid BINARY(16);
  SET v_tid=UUID_TO_BIN(p_tenant,1);
  IF get_tenant() IS NULL OR get_tenant()<>v_tid THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='tenant mismatch'; END IF;
  INSERT INTO users(tenant_id,full_name,role,pii_wrapped_key,pii_pq_wrapped_key,pq_alg,kms_key_name,email_ct,email_iv,email_aad,phone_ct,phone_iv,phone_aad)
  VALUES(v_tid,p_name,p_role,p_wrapped_key,p_pq_wrapped,p_pq_alg,p_kms_key_name,p_email_ct,p_email_iv,p_email_aad,p_phone_ct,p_phone_iv,p_phone_aad);
  SELECT id INTO v_uid FROM users WHERE tenant_id=v_tid AND full_name=p_name ORDER BY created_at DESC LIMIT 1;
  SET o_user_id=BIN_TO_UUID(v_uid,1);
END$$

CREATE DEFINER='api_definer'@'localhost' PROCEDURE app_open_account(IN p_tenant CHAR(36), IN p_owner CHAR(36), IN p_initial BIGINT) SQL SECURITY DEFINER
BEGIN
  DECLARE v_tid BINARY(16); DECLARE v_owner BINARY(16);
  IF p_initial<0 THEN SIGNAL SQLSTATE '22003' SET MESSAGE_TEXT='bad amount'; END IF;
  SET v_tid=UUID_TO_BIN(p_tenant,1); SET v_owner=UUID_TO_BIN(p_owner,1);
  IF get_tenant() IS NULL OR get_tenant()<>v_tid THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='tenant mismatch'; END IF;
  IF NOT EXISTS(SELECT 1 FROM users WHERE id=v_owner AND tenant_id=v_tid) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owner not in tenant'; END IF;
  INSERT INTO accounts(tenant_id,owner_user,balance_cents) VALUES(v_tid,v_owner,p_initial);
END$$

CREATE DEFINER='api_definer'@'localhost' PROCEDURE app_transfer(IN p_tenant CHAR(36), IN p_from CHAR(36), IN p_to CHAR(36), IN p_amount BIGINT) SQL SECURITY DEFINER
BEGIN
  DECLARE v_tid BINARY(16); DECLARE v_from BINARY(16); DECLARE v_to BINARY(16);
  IF p_amount<=0 THEN SIGNAL SQLSTATE '22003' SET MESSAGE_TEXT='bad amount'; END IF;
  SET v_tid=UUID_TO_BIN(p_tenant,1); SET v_from=UUID_TO_BIN(p_from,1); SET v_to=UUID_TO_BIN(p_to,1);
  IF get_tenant() IS NULL OR get_tenant()<>v_tid THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='tenant mismatch'; END IF;
  IF NOT EXISTS(SELECT 1 FROM accounts WHERE id=v_from AND tenant_id=v_tid) OR NOT EXISTS(SELECT 1 FROM accounts WHERE id=v_to AND tenant_id=v_tid) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='cross-tenant'; END IF;
  START TRANSACTION;
    UPDATE accounts SET balance_cents=balance_cents-p_amount WHERE id=v_from;
    IF ROW_COUNT()=0 THEN ROLLBACK; SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='from missing'; END IF;
    UPDATE accounts SET balance_cents=balance_cents+p_amount WHERE id=v_to;
  COMMIT;
END$$

CREATE DEFINER='api_definer'@'localhost' VIEW v_users AS SELECT BIN_TO_UUID(u.id,1) id,BIN_TO_UUID(u.tenant_id,1) tenant_id,u.full_name,u.role,u.created_at FROM users u WHERE u.tenant_id=get_tenant();
CREATE DEFINER='api_definer'@'localhost' VIEW v_accounts AS SELECT BIN_TO_UUID(a.id,1) id,BIN_TO_UUID(a.tenant_id,1) tenant_id,BIN_TO_UUID(a.owner_user,1) owner_user,a.balance_cents,a.created_at FROM accounts a WHERE a.tenant_id=get_tenant();

CREATE DEFINER='api_definer'@'localhost' PROCEDURE audit_log_event(IN p_table VARCHAR(64),IN p_action ENUM('INSERT','UPDATE','DELETE'),IN p_pk VARCHAR(64),IN p_before JSON,IN p_after JSON) SQL SECURITY DEFINER
BEGIN
  DECLARE v_prev VARBINARY(32); DECLARE v_tenant CHAR(36);
  SELECT curr_hash INTO v_prev FROM audit_events ORDER BY id DESC LIMIT 1;
  SELECT BIN_TO_UUID(tenant_id,1) INTO v_tenant FROM session_ctx WHERE conn_id=CONNECTION_ID();
  INSERT INTO audit_events(actor,app_tenant,table_name,action,pk_text,before_doc,after_doc,client_addr,prev_hash,curr_hash)
  VALUES(CURRENT_USER(),v_tenant,p_table,p_action,p_pk,p_before,p_after,SUBSTRING_INDEX(USER(),'@',-1),v_prev,UNHEX(SHA2(CONCAT(IFNULL(HEX(v_prev),''),'|',IFNULL(v_tenant,''),'|',p_table,'|',p_action,'|',IFNULL(p_pk,''),'|',JSON_EXTRACT(IFNULL(p_before,JSON_OBJECT()),'$'),'|',JSON_EXTRACT(IFNULL(p_after,JSON_OBJECT()),'$'),'|',NOW()),256)));
END$$

DROP TRIGGER IF EXISTS trg_users_ins; DROP TRIGGER IF EXISTS trg_users_upd; DROP TRIGGER IF EXISTS trg_users_del;
CREATE DEFINER='api_definer'@'localhost' TRIGGER trg_users_ins AFTER INSERT ON users FOR EACH ROW BEGIN CALL audit_log_event('users','INSERT',BIN_TO_UUID(NEW.id,1),NULL,JSON_OBJECT('id',BIN_TO_UUID(NEW.id,1),'tenant',BIN_TO_UUID(NEW.tenant_id,1),'full_name',NEW.full_name,'role',NEW.role,'created_at',NEW.created_at)); END$$
CREATE DEFINER='api_definer'@'localhost' TRIGGER trg_users_upd AFTER UPDATE ON users FOR EACH ROW BEGIN CALL audit_log_event('users','UPDATE',BIN_TO_UUID(NEW.id,1),JSON_OBJECT('id',BIN_TO_UUID(OLD.id,1),'tenant',BIN_TO_UUID(OLD.tenant_id,1),'full_name',OLD.full_name,'role',OLD.role,'created_at',OLD.created_at),JSON_OBJECT('id',BIN_TO_UUID(NEW.id,1),'tenant',BIN_TO_UUID(NEW.tenant_id,1),'full_name',NEW.full_name,'role',NEW.role,'created_at',NEW.created_at)); END$$
CREATE DEFINER='api_definer'@'localhost' TRIGGER trg_users_del AFTER DELETE ON users FOR EACH ROW BEGIN CALL audit_log_event('users','DELETE',BIN_TO_UUID(OLD.id,1),JSON_OBJECT('id',BIN_TO_UUID(OLD.id,1),'tenant',BIN_TO_UUID(OLD.tenant_id,1),'full_name',OLD.full_name,'role',OLD.role,'created_at',OLD.created_at),NULL); END$$

DROP TRIGGER IF EXISTS trg_accounts_ins; DROP TRIGGER IF EXISTS trg_accounts_upd; DROP TRIGGER IF EXISTS trg_accounts_del;
CREATE DEFINER='api_definer'@'localhost' TRIGGER trg_accounts_ins AFTER INSERT ON accounts FOR EACH ROW BEGIN CALL audit_log_event('accounts','INSERT',BIN_TO_UUID(NEW.id,1),NULL,JSON_OBJECT('id',BIN_TO_UUID(NEW.id,1),'tenant',BIN_TO_UUID(NEW.tenant_id,1),'owner_user',BIN_TO_UUID(NEW.owner_user,1),'balance_cents',NEW.balance_cents,'created_at',NEW.created_at)); END$$
CREATE DEFINER='api_definer'@'localhost' TRIGGER trg_accounts_upd AFTER UPDATE ON accounts FOR EACH ROW BEGIN CALL audit_log_event('accounts','UPDATE',BIN_TO_UUID(NEW.id,1),JSON_OBJECT('id',BIN_TO_UUID(OLD.id,1),'tenant',BIN_TO_UUID(OLD.tenant_id,1),'owner_user',BIN_TO_UUID(OLD.owner_user,1),'balance_cents',OLD.balance_cents,'created_at',OLD.created_at),JSON_OBJECT('id',BIN_TO_UUID(NEW.id,1),'tenant',BIN_TO_UUID(NEW.tenant_id,1),'owner_user',BIN_TO_UUID(NEW.owner_user,1),'balance_cents',NEW.balance_cents,'created_at',NEW.created_at)); END$$
CREATE DEFINER='api_definer'@'localhost' TRIGGER trg_accounts_del AFTER DELETE ON accounts FOR EACH ROW BEGIN CALL audit_log_event('accounts','DELETE',BIN_TO_UUID(OLD.id,1),JSON_OBJECT('id',BIN_TO_UUID(OLD.id,1),'tenant',BIN_TO_UUID(OLD.tenant_id,1),'owner_user',BIN_TO_UUID(OLD.owner_user,1),'balance_cents',OLD.balance_cents,'created_at',OLD.created_at),NULL); END$$

CREATE TRIGGER audit_events_block_upd BEFORE UPDATE ON audit_events FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append-only'; END$$
CREATE TRIGGER audit_events_block_del BEFORE DELETE ON audit_events FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append-only'; END$$
DELIMITER ;

INSERT IGNORE INTO tenants(name) VALUES('Acme Corp'),('Globex Ltd');

REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'app_user'@'localhost','auditor'@'localhost','migration'@'localhost','db_owner'@'localhost';
GRANT USAGE ON *.* TO 'app_user'@'localhost','auditor'@'localhost','migration'@'localhost';
GRANT SELECT ON securedb.v_users TO 'app_user'@'localhost';
GRANT SELECT ON securedb.v_accounts TO 'app_user'@'localhost';
GRANT EXECUTE ON PROCEDURE securedb.security_set_tenant TO 'app_user'@'localhost';
GRANT EXECUTE ON PROCEDURE securedb.app_create_user_encrypted TO 'app_user'@'localhost';
GRANT EXECUTE ON PROCEDURE securedb.app_open_account TO 'app_user'@'localhost';
GRANT EXECUTE ON PROCEDURE securedb.app_transfer TO 'app_user'@'localhost';
GRANT SELECT ON securedb.audit_events TO 'auditor'@'localhost';
GRANT EXECUTE ON PROCEDURE securedb.security_set_tenant TO 'auditor'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,INDEX,DROP ON securedb.* TO 'migration'@'localhost';
ALTER USER 'app_user'@'localhost' REQUIRE X509;
ALTER USER 'auditor'@'localhost' REQUIRE X509;
FLUSH PRIVILEGES;
SQL_EOF
)
echo "$SQL" | $ROOT_MYSQL

tee /opt/anchor_head.sh >/dev/null <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
H=$(mysql -N -e "SELECT HEX(curr_hash) FROM securedb.audit_events ORDER BY id DESC LIMIT 1;" || true)
[ -n "${H:-}" ] && logger -t securedb "AUDIT_CHAIN_HEAD ${H}"
EOS
chmod 750 /opt/anchor_head.sh

tee /etc/systemd/system/securedb-anchor.service >/dev/null <<'EOS'
[Unit]
Description=SecureDB Anchor Head
[Service]
Type=oneshot
ExecStart=/opt/anchor_head.sh
User=root
Group=root
RuntimeMaxSec=30
EOS

tee /etc/systemd/system/securedb-anchor.timer >/dev/null <<'EOS'
[Unit]
Description=SecureDB Anchor Head Timer
[Timer]
OnCalendar=*:0/1
Persistent=true
[Install]
WantedBy=timers.target
EOS

systemctl daemon-reload
systemctl enable --now securedb-anchor.timer
systemctl enable --now fail2ban || true

if command -v ufw >/dev/null; then
  ufw default deny incoming || true
  ufw default allow outgoing || true
  ufw allow 22/tcp || true
  if [[ "$ALLOW_REMOTE" = "1" ]]; then
    IFS=, read -ra CIDRS <<< "$ALLOWED_CIDR"
    for C in "${CIDRS[@]}"; do ufw allow from "$C" to any port 3306 proto tcp || true; done
  fi
  yes | ufw enable || true
fi

echo "OK"