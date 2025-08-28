-- securedb_inventory_demo.sql
-- Inventory domain for Zero-Trust MySQL: parts lifecycle, shipments, installs, replacements, full audit
-- Uses proc-only writes, tenant scoping, tamper-evident audit. It seeds realistic demo data and exposes tenant-scoped views only.

-- Assumptions:
-- - Database: securedb (existing)
-- - Tenant model exists or we seed a demo tenant
-- - app_user will get EXECUTE on procs and SELECT on v_* views
-- - audit_events table either exists with compatible columns; created here if missing

USE securedb;

SET SESSION sql_require_primary_key = 1;
SET SESSION innodb_strict_mode = ON;
SET SESSION sql_mode = 'STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- ---------- Helpers: tenant context ----------
DROP FUNCTION IF EXISTS security_get_tenant;
DELIMITER $$
CREATE FUNCTION security_get_tenant() RETURNS BINARY(16)
DETERMINISTIC
BEGIN
  RETURN @tenant_uuid_bin;
END$$
DELIMITER ;

DROP PROCEDURE IF EXISTS security_set_tenant;
DELIMITER $$
CREATE PROCEDURE security_set_tenant(p_tenant_uuid CHAR(36))
SQL SECURITY INVOKER
BEGIN
  SET @tenant_uuid_bin = UUID_TO_BIN(p_tenant_uuid, 1);
END$$
DELIMITER ;

-- ---------- Minimal tenants table (only if not present) ----------
-- If the base already has tenants, this CREATE IF NOT EXISTS is compatible.
CREATE TABLE IF NOT EXISTS tenants (
  id BINARY(16) NOT NULL PRIMARY KEY,
  name VARCHAR(200) NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Seed demo tenant if not present
INSERT IGNORE INTO tenants (id, name)
VALUES (UUID_TO_BIN('11111111-1111-4111-8111-111111111111',1), 'Demo Motors Ltd');

-- ---------- Audit table (create if missing) ----------
CREATE TABLE IF NOT EXISTS audit_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ts TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  actor VARCHAR(255) NOT NULL,
  tenant_id BINARY(16) NULL,
  table_name VARCHAR(128) NOT NULL,
  action ENUM('INSERT','UPDATE','DELETE') NOT NULL,
  row_pk VARCHAR(128) NOT NULL,
  prev_hash BINARY(32) NULL,
  curr_hash BINARY(32) NOT NULL,
  payload JSON NOT NULL,
  KEY (tenant_id),
  KEY (table_name),
  KEY (ts)
) ENGINE=InnoDB;

-- ---------- Audit helper ----------
DROP PROCEDURE IF EXISTS p_audit_log;
DELIMITER $$
CREATE PROCEDURE p_audit_log(
  IN p_table VARCHAR(128),
  IN p_action ENUM('INSERT','UPDATE','DELETE'),
  IN p_row_pk VARCHAR(128),
  IN p_payload JSON
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_prev BINARY(32);
  DECLARE v_curr BINARY(32);
  DECLARE v_tenant BINARY(16);

  SET v_tenant = security_get_tenant();

  SELECT curr_hash INTO v_prev
  FROM audit_events
  WHERE (tenant_id <=> v_tenant OR (tenant_id IS NULL AND v_tenant IS NULL))
  ORDER BY id DESC LIMIT 1;

  SET v_curr = UNHEX(SHA2(CONCAT(COALESCE(HEX(v_prev),''), JSON_EXTRACT(p_payload,'$')), 256));

  INSERT INTO audit_events(actor, tenant_id, table_name, action, row_pk, prev_hash, curr_hash, payload)
  VALUES (CURRENT_USER(), v_tenant, p_table, p_action, p_row_pk, v_prev, v_curr, p_payload);
END$$
DELIMITER ;

-- ---------- Core master data ----------
DROP TABLE IF EXISTS oems;
CREATE TABLE oems (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  name VARCHAR(200) NOT NULL,
  country VARCHAR(100) NOT NULL,
  UNIQUE KEY uq_oem_tenant_name (tenant_id, name),
  KEY (tenant_id),
  CONSTRAINT fk_oems_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS manufacturing_sites;
CREATE TABLE manufacturing_sites (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  oem_id BINARY(16) NOT NULL,
  code VARCHAR(50) NOT NULL,
  name VARCHAR(200) NOT NULL,
  address VARCHAR(500),
  lat DECIMAL(9,6),
  lon DECIMAL(9,6),
  UNIQUE KEY uq_site_tenant_code (tenant_id, code),
  KEY (oem_id),
  KEY (tenant_id),
  CONSTRAINT fk_sites_oem FOREIGN KEY (oem_id) REFERENCES oems(id),
  CONSTRAINT fk_sites_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS warehouses;
CREATE TABLE warehouses (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  code VARCHAR(50) NOT NULL,
  name VARCHAR(200) NOT NULL,
  address VARCHAR(500),
  lat DECIMAL(9,6),
  lon DECIMAL(9,6),
  UNIQUE KEY uq_wh_tenant_code (tenant_id, code),
  KEY (tenant_id),
  CONSTRAINT fk_wh_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS carriers;
CREATE TABLE carriers (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  name VARCHAR(200) NOT NULL,
  mode ENUM('TRUCK','RAIL','AIR','SEA') NOT NULL,
  contact JSON,
  UNIQUE KEY uq_carrier_tenant_name (tenant_id, name),
  KEY (tenant_id),
  CONSTRAINT fk_carrier_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS part_models;
CREATE TABLE part_models (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  oem_id BINARY(16) NOT NULL,
  sku VARCHAR(100) NOT NULL,
  name VARCHAR(200) NOT NULL,
  category VARCHAR(100) NOT NULL,
  specs JSON,
  service_life_km INT UNSIGNED,
  service_life_months INT UNSIGNED,
  superseded_by BINARY(16) NULL,
  UNIQUE KEY uq_model_tenant_sku (tenant_id, sku),
  KEY (oem_id),
  KEY (tenant_id),
  CONSTRAINT fk_model_oem FOREIGN KEY (oem_id) REFERENCES oems(id),
  CONSTRAINT fk_model_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS part_model_compatibility;
CREATE TABLE part_model_compatibility (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  model_id BINARY(16) NOT NULL,
  replacement_id BINARY(16) NOT NULL,
  relation ENUM('OEM_EQUIV','AFTERMARKET_EQUIV','SUPERSEDES','SUPERSEDED_BY') NOT NULL,
  effective_from DATE NOT NULL,
  effective_to DATE NULL,
  notes VARCHAR(500),
  UNIQUE KEY uq_model_replacement (tenant_id, model_id, replacement_id, relation, effective_from),
  KEY (tenant_id),
  KEY (model_id),
  KEY (replacement_id),
  CONSTRAINT fk_comp_model FOREIGN KEY (model_id) REFERENCES part_models(id),
  CONSTRAINT fk_comp_repl FOREIGN KEY (replacement_id) REFERENCES part_models(id),
  CONSTRAINT fk_comp_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

-- ---------- Production & serialisation ----------
DROP TABLE IF EXISTS part_batches;
CREATE TABLE part_batches (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  part_model_id BINARY(16) NOT NULL,
  site_id BINARY(16) NOT NULL,
  lot_no VARCHAR(100) NOT NULL,
  mfg_date DATE NOT NULL,
  qty_planned INT UNSIGNED NOT NULL,
  qc_status ENUM('PENDING','PASS','FAIL','PARTIAL') NOT NULL DEFAULT 'PENDING',
  UNIQUE KEY uq_batch (tenant_id, part_model_id, site_id, lot_no, mfg_date),
  KEY (tenant_id),
  KEY (part_model_id),
  KEY (site_id),
  CONSTRAINT fk_batch_model FOREIGN KEY (part_model_id) REFERENCES part_models(id),
  CONSTRAINT fk_batch_site FOREIGN KEY (site_id) REFERENCES manufacturing_sites(id),
  CONSTRAINT fk_batch_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS parts;
CREATE TABLE parts (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  batch_id BINARY(16) NOT NULL,
  serial_no VARCHAR(120) NOT NULL,
  status ENUM('MANUFACTURED','QC_PASS','QC_FAIL','IN_TRANSIT','IN_WAREHOUSE','INSTALLED','RETURNED','SCRAPPED','REFURBISHED') NOT NULL DEFAULT 'MANUFACTURED',
  current_location_type ENUM('PLANT','WAREHOUSE','IN_TRANSIT','VEHICLE','UNKNOWN') NOT NULL DEFAULT 'PLANT',
  current_location_id BINARY(16) NULL,
  manufactured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_serial (tenant_id, serial_no),
  KEY (tenant_id),
  KEY (batch_id),
  CONSTRAINT fk_parts_batch FOREIGN KEY (batch_id) REFERENCES part_batches(id),
  CONSTRAINT fk_parts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

-- ---------- Logistics ----------
DROP TABLE IF EXISTS shipments;
CREATE TABLE shipments (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  from_type ENUM('PLANT','WAREHOUSE') NOT NULL,
  from_id BINARY(16) NOT NULL,
  to_type ENUM('WAREHOUSE','PLANT','CUSTOMER') NOT NULL,
  to_id BINARY(16) NOT NULL,
  status ENUM('PLANNED','IN_TRANSIT','DELIVERED','CANCELLED') NOT NULL DEFAULT 'PLANNED',
  incoterm VARCHAR(16),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY (tenant_id),
  CONSTRAINT fk_ship_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS shipment_legs;
CREATE TABLE shipment_legs (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  shipment_id BINARY(16) NOT NULL,
  seq INT UNSIGNED NOT NULL,
  carrier_id BINARY(16) NOT NULL,
  mode ENUM('TRUCK','RAIL','AIR','SEA') NOT NULL,
  depart_planned TIMESTAMP NULL,
  arrive_planned TIMESTAMP NULL,
  depart_actual TIMESTAMP NULL,
  arrive_actual TIMESTAMP NULL,
  route JSON,
  UNIQUE KEY uq_leg (tenant_id, shipment_id, seq),
  KEY (tenant_id),
  KEY (shipment_id),
  CONSTRAINT fk_leg_ship FOREIGN KEY (shipment_id) REFERENCES shipments(id),
  CONSTRAINT fk_leg_carrier FOREIGN KEY (carrier_id) REFERENCES carriers(id),
  CONSTRAINT fk_leg_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS shipment_items;
CREATE TABLE shipment_items (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  shipment_id BINARY(16) NOT NULL,
  part_id BINARY(16) NOT NULL,
  UNIQUE KEY uq_item (tenant_id, shipment_id, part_id),
  KEY (tenant_id),
  KEY (shipment_id),
  KEY (part_id),
  CONSTRAINT fk_item_ship FOREIGN KEY (shipment_id) REFERENCES shipments(id),
  CONSTRAINT fk_item_part FOREIGN KEY (part_id) REFERENCES parts(id),
  CONSTRAINT fk_item_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS leg_gps_events;
CREATE TABLE leg_gps_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  leg_id BINARY(16) NOT NULL,
  ts TIMESTAMP(6) NOT NULL,
  lat DECIMAL(9,6) NOT NULL,
  lon DECIMAL(9,6) NOT NULL,
  speed_kmh DECIMAL(8,2) NULL,
  heading_deg DECIMAL(6,2) NULL,
  KEY (tenant_id),
  KEY (leg_id, ts),
  CONSTRAINT fk_gps_leg FOREIGN KEY (leg_id) REFERENCES shipment_legs(id),
  CONSTRAINT fk_gps_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

-- ---------- Vehicles & installations ----------
DROP TABLE IF EXISTS vehicles;
CREATE TABLE vehicles (
  vin CHAR(17) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  make VARCHAR(80) NOT NULL,
  model VARCHAR(80) NOT NULL,
  year SMALLINT NOT NULL,
  trim VARCHAR(80),
  UNIQUE KEY uq_vehicle (tenant_id, vin),
  KEY (tenant_id),
  CONSTRAINT fk_vehicle_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

DROP TABLE IF EXISTS installations;
CREATE TABLE installations (
  id BINARY(16) NOT NULL PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  part_id BINARY(16) NOT NULL,
  vin CHAR(17) NOT NULL,
  position VARCHAR(80) NOT NULL, -- e.g., BRAKE-FRONT-LEFT
  installed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  removed_at TIMESTAMP NULL,
  removal_reason VARCHAR(200) NULL,
  replaced_by_part_id BINARY(16) NULL,
  KEY (tenant_id),
  KEY (part_id),
  KEY (vin),
  CONSTRAINT fk_inst_part FOREIGN KEY (part_id) REFERENCES parts(id),
  CONSTRAINT fk_inst_vehicle FOREIGN KEY (vin) REFERENCES vehicles(vin),
  CONSTRAINT fk_inst_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

-- ---------- Stock ledger (movement audit) ----------
DROP TABLE IF EXISTS stock_ledger;
CREATE TABLE stock_ledger (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  part_id BINARY(16) NULL,
  part_model_id BINARY(16) NULL,
  from_type ENUM('PLANT','WAREHOUSE','IN_TRANSIT','VEHICLE','NULL') NOT NULL,
  from_id BINARY(16) NULL,
  to_type ENUM('PLANT','WAREHOUSE','IN_TRANSIT','VEHICLE','NULL') NOT NULL,
  to_id BINARY(16) NULL,
  qty INT NOT NULL DEFAULT 1,
  reason ENUM('PRODUCTION','QC_PASS','QC_FAIL','SHIPMENT_OUT','SHIPMENT_IN','INSTALL','REMOVE','ADJUST','SCRAP') NOT NULL,
  ref_table VARCHAR(64) NULL,
  ref_id VARCHAR(128) NULL,
  ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY (tenant_id),
  KEY (part_id),
  KEY (part_model_id),
  CONSTRAINT fk_ledger_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

-- ---------- VIEWS (tenant-scoped) ----------
DROP VIEW IF EXISTS v_part_models;
CREATE VIEW v_part_models AS
SELECT
  BIN_TO_UUID(pm.id,1) AS part_model_id,
  BIN_TO_UUID(pm.tenant_id,1) AS tenant_id,
  o.name AS oem_name,
  pm.sku, pm.name, pm.category, pm.specs,
  pm.service_life_km, pm.service_life_months,
  BIN_TO_UUID(pm.superseded_by,1) AS superseded_by
FROM part_models pm
JOIN oems o ON o.id = pm.oem_id
WHERE pm.tenant_id <=> security_get_tenant();

DROP VIEW IF EXISTS v_parts;
CREATE VIEW v_parts AS
SELECT
  BIN_TO_UUID(p.id,1) AS part_id,
  BIN_TO_UUID(p.tenant_id,1) AS tenant_id,
  BIN_TO_UUID(p.batch_id,1) AS batch_id,
  p.serial_no, p.status, p.current_location_type,
  BIN_TO_UUID(p.current_location_id,1) AS current_location_id,
  p.manufactured_at
FROM parts p
WHERE p.tenant_id <=> security_get_tenant();

DROP VIEW IF EXISTS v_shipments;
CREATE VIEW v_shipments AS
SELECT
  BIN_TO_UUID(s.id,1) AS shipment_id,
  s.from_type, BIN_TO_UUID(s.from_id,1) AS from_id,
  s.to_type,   BIN_TO_UUID(s.to_id,1) AS to_id,
  s.status, s.incoterm, s.created_at
FROM shipments s
WHERE s.tenant_id <=> security_get_tenant();

DROP VIEW IF EXISTS v_installations;
CREATE VIEW v_installations AS
SELECT
  BIN_TO_UUID(i.id,1) AS installation_id,
  BIN_TO_UUID(i.part_id,1) AS part_id,
  i.vin, i.position, i.installed_at, i.removed_at, i.removal_reason,
  BIN_TO_UUID(i.replaced_by_part_id,1) AS replaced_by_part_id
FROM installations i
WHERE i.tenant_id <=> security_get_tenant();

DROP VIEW IF EXISTS v_replacements;
CREATE VIEW v_replacements AS
SELECT
  BIN_TO_UUID(c.model_id,1) AS model_id,
  BIN_TO_UUID(c.replacement_id,1) AS replacement_id,
  c.relation, c.effective_from, c.effective_to, c.notes
FROM part_model_compatibility c
WHERE c.tenant_id <=> security_get_tenant();

-- ---------- Triggers -> audit ----------
DELIMITER $$

DROP TRIGGER IF EXISTS trg_parts_ai$$
CREATE TRIGGER trg_parts_ai AFTER INSERT ON parts
FOR EACH ROW BEGIN
  CALL p_audit_log('parts','INSERT', BIN_TO_UUID(NEW.id,1),
    JSON_OBJECT('serial_no', NEW.serial_no, 'status', NEW.status, 'batch', BIN_TO_UUID(NEW.batch_id,1)));
END$$

DROP TRIGGER IF EXISTS trg_parts_au$$
CREATE TRIGGER trg_parts_au AFTER UPDATE ON parts
FOR EACH ROW BEGIN
  CALL p_audit_log('parts','UPDATE', BIN_TO_UUID(NEW.id,1),
    JSON_OBJECT('old_status', OLD.status, 'new_status', NEW.status,
                'old_loc', OLD.current_location_type, 'new_loc', NEW.current_location_type));
END$$

DROP TRIGGER IF EXISTS trg_parts_ad$$
CREATE TRIGGER trg_parts_ad AFTER DELETE ON parts
FOR EACH ROW BEGIN
  CALL p_audit_log('parts','DELETE', BIN_TO_UUID(OLD.id,1),
    JSON_OBJECT('serial_no', OLD.serial_no, 'status', OLD.status));
END$$

DROP TRIGGER IF EXISTS trg_shipments_ai$$
CREATE TRIGGER trg_shipments_ai AFTER INSERT ON shipments
FOR EACH ROW BEGIN
  CALL p_audit_log('shipments','INSERT', BIN_TO_UUID(NEW.id,1),
    JSON_OBJECT('from', NEW.from_type, 'to', NEW.to_type, 'status', NEW.status));
END$$

DROP TRIGGER IF EXISTS trg_shipments_au$$
CREATE TRIGGER trg_shipments_au AFTER UPDATE ON shipments
FOR EACH ROW BEGIN
  CALL p_audit_log('shipments','UPDATE', BIN_TO_UUID(NEW.id,1),
    JSON_OBJECT('old_status', OLD.status, 'new_status', NEW.status));
END$$

DROP TRIGGER IF EXISTS trg_shipment_items_ai$$
CREATE TRIGGER trg_shipment_items_ai AFTER INSERT ON shipment_items
FOR EACH ROW BEGIN
  CALL p_audit_log('shipment_items','INSERT', BIN_TO_UUID(NEW.id,1),
    JSON_OBJECT('shipment', BIN_TO_UUID(NEW.shipment_id,1), 'part', BIN_TO_UUID(NEW.part_id,1)));
END$$

DROP TRIGGER IF EXISTS trg_installations_ai$$
CREATE TRIGGER trg_installations_ai AFTER INSERT ON installations
FOR EACH ROW BEGIN
  CALL p_audit_log('installations','INSERT', BIN_TO_UUID(NEW.id,1),
    JSON_OBJECT('part', BIN_TO_UUID(NEW.part_id,1), 'vin', NEW.vin, 'position', NEW.position));
END$$

DROP TRIGGER IF EXISTS trg_stock_ledger_ai$$
CREATE TRIGGER trg_stock_ledger_ai AFTER INSERT ON stock_ledger
FOR EACH ROW BEGIN
  CALL p_audit_log('stock_ledger','INSERT', CAST(NEW.id AS CHAR),
    JSON_OBJECT('reason', NEW.reason, 'from', NEW.from_type, 'to', NEW.to_type, 'qty', NEW.qty));
END$$

DELIMITER ;

-- ---------- Procedures (proc-only writes) ----------
-- Create OEM
DROP PROCEDURE IF EXISTS p_create_oem;
DELIMITER $$
CREATE PROCEDURE p_create_oem(
  IN p_name VARCHAR(200),
  IN p_country VARCHAR(100)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO oems(id, tenant_id, name, country)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, p_name, p_country);
END$$
DELIMITER ;

-- Create manufacturing site
DROP PROCEDURE IF EXISTS p_create_site;
DELIMITER $$
CREATE PROCEDURE p_create_site(
  IN p_oem_uuid CHAR(36),
  IN p_code VARCHAR(50),
  IN p_name VARCHAR(200),
  IN p_address VARCHAR(500),
  IN p_lat DECIMAL(9,6),
  IN p_lon DECIMAL(9,6)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO manufacturing_sites(id, tenant_id, oem_id, code, name, address, lat, lon)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, UUID_TO_BIN(p_oem_uuid,1), p_code, p_name, p_address, p_lat, p_lon);
END$$
DELIMITER ;

-- Create warehouse
DROP PROCEDURE IF EXISTS p_create_warehouse;
DELIMITER $$
CREATE PROCEDURE p_create_warehouse(
  IN p_code VARCHAR(50),
  IN p_name VARCHAR(200),
  IN p_address VARCHAR(500),
  IN p_lat DECIMAL(9,6),
  IN p_lon DECIMAL(9,6)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO warehouses(id, tenant_id, code, name, address, lat, lon)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, p_code, p_name, p_address, p_lat, p_lon);
END$$
DELIMITER ;

-- Register part model
DROP PROCEDURE IF EXISTS p_register_part_model;
DELIMITER $$
CREATE PROCEDURE p_register_part_model(
  IN p_oem_uuid CHAR(36),
  IN p_sku VARCHAR(100),
  IN p_name VARCHAR(200),
  IN p_category VARCHAR(100),
  IN p_specs JSON,
  IN p_service_life_km INT,
  IN p_service_life_months INT
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();

  INSERT INTO part_models(id, tenant_id, oem_id, sku, name, category, specs, service_life_km, service_life_months)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, UUID_TO_BIN(p_oem_uuid,1), p_sku, p_name, p_category, p_specs, p_service_life_km, p_service_life_months);
END$$
DELIMITER ;

-- Mark model replacement mapping
DROP PROCEDURE IF EXISTS p_mark_replacement;
DELIMITER $$
CREATE PROCEDURE p_mark_replacement(
  IN p_model_uuid CHAR(36),
  IN p_replacement_uuid CHAR(36),
  IN p_relation ENUM('OEM_EQUIV','AFTERMARKET_EQUIV','SUPERSEDES','SUPERSEDED_BY'),
  IN p_from DATE,
  IN p_to DATE,
  IN p_notes VARCHAR(500)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO part_model_compatibility(id, tenant_id, model_id, replacement_id, relation, effective_from, effective_to, notes)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, UUID_TO_BIN(p_model_uuid,1), UUID_TO_BIN(p_replacement_uuid,1),
          p_relation, p_from, p_to, p_notes);
END$$
DELIMITER ;

-- Create batch
DROP PROCEDURE IF EXISTS p_create_batch;
DELIMITER $$
CREATE PROCEDURE p_create_batch(
  IN p_part_model_uuid CHAR(36),
  IN p_site_uuid CHAR(36),
  IN p_lot_no VARCHAR(100),
  IN p_mfg_date DATE,
  IN p_qty INT
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO part_batches(id, tenant_id, part_model_id, site_id, lot_no, mfg_date, qty_planned)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, UUID_TO_BIN(p_part_model_uuid,1), UUID_TO_BIN(p_site_uuid,1), p_lot_no, p_mfg_date, p_qty);
END$$
DELIMITER ;

-- Generate serialised parts in a batch
DROP PROCEDURE IF EXISTS p_generate_serials;
DELIMITER $$
CREATE PROCEDURE p_generate_serials(
  IN p_batch_uuid CHAR(36),
  IN p_prefix VARCHAR(40),
  IN p_count INT
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  DECLARE v_i INT DEFAULT 1;
  DECLARE v_batch BINARY(16) DEFAULT UUID_TO_BIN(p_batch_uuid,1);

  WHILE v_i <= p_count DO
    INSERT INTO parts (id, tenant_id, batch_id, serial_no)
    VALUES (UUID_TO_BIN(UUID(),1), v_tenant, v_batch, CONCAT(p_prefix, LPAD(v_i, 6, '0')));
    SET v_i = v_i + 1;
  END WHILE;

  INSERT INTO stock_ledger(tenant_id, part_model_id, from_type, from_id, to_type, to_id, qty, reason, ref_table, ref_id)
  SELECT v_tenant, pb.part_model_id, 'NULL', NULL, 'PLANT', pb.site_id, p_count, 'PRODUCTION', 'part_batches', BIN_TO_UUID(v_batch,1)
  FROM part_batches pb WHERE pb.id = v_batch;
END$$
DELIMITER ;

-- QC set result
DROP PROCEDURE IF EXISTS p_qc_set;
DELIMITER $$
CREATE PROCEDURE p_qc_set(
  IN p_serial_uuid CHAR(36),
  IN p_result ENUM('PASS','FAIL')
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_id BINARY(16) DEFAULT UUID_TO_BIN(p_serial_uuid,1);
  UPDATE parts SET status = IF(p_result='PASS','QC_PASS','QC_FAIL') WHERE id = v_id;

  IF p_result='PASS' THEN
    INSERT INTO stock_ledger(tenant_id, part_id, from_type, to_type, qty, reason, ref_table, ref_id)
    SELECT tenant_id, id, 'PLANT', 'PLANT', 1, 'QC_PASS', 'parts', p_serial_uuid FROM parts WHERE id=v_id;
  ELSE
    INSERT INTO stock_ledger(tenant_id, part_id, from_type, to_type, qty, reason, ref_table, ref_id)
    SELECT tenant_id, id, 'PLANT', 'PLANT', 1, 'QC_FAIL', 'parts', p_serial_uuid FROM parts WHERE id=v_id;
  END IF;
END$$
DELIMITER ;

-- Create shipment
DROP PROCEDURE IF EXISTS p_create_shipment;
DELIMITER $$
CREATE PROCEDURE p_create_shipment(
  IN p_from_type ENUM('PLANT','WAREHOUSE'),
  IN p_from_uuid CHAR(36),
  IN p_to_type ENUM('WAREHOUSE','PLANT','CUSTOMER'),
  IN p_to_uuid CHAR(36)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO shipments(id, tenant_id, from_type, from_id, to_type, to_id)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, p_from_type, UUID_TO_BIN(p_from_uuid,1), p_to_type, UUID_TO_BIN(p_to_uuid,1));
END$$
DELIMITER ;

-- Add leg to shipment
DROP PROCEDURE IF EXISTS p_add_leg;
DELIMITER $$
CREATE PROCEDURE p_add_leg(
  IN p_shipment_uuid CHAR(36),
  IN p_seq INT,
  IN p_carrier_uuid CHAR(36),
  IN p_mode ENUM('TRUCK','RAIL','AIR','SEA'),
  IN p_depart_planned TIMESTAMP,
  IN p_arrive_planned TIMESTAMP
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  INSERT INTO shipment_legs(id, tenant_id, shipment_id, seq, carrier_id, mode, depart_planned, arrive_planned)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, UUID_TO_BIN(p_shipment_uuid,1), p_seq, UUID_TO_BIN(p_carrier_uuid,1), p_mode, p_depart_planned, p_arrive_planned);
END$$
DELIMITER ;

-- Put part into shipment
DROP PROCEDURE IF EXISTS p_add_shipment_item;
DELIMITER $$
CREATE PROCEDURE p_add_shipment_item(
  IN p_shipment_uuid CHAR(36),
  IN p_part_uuid CHAR(36)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  DECLARE v_part BINARY(16) DEFAULT UUID_TO_BIN(p_part_uuid,1);

  UPDATE parts SET status='IN_TRANSIT', current_location_type='IN_TRANSIT', current_location_id=NULL
  WHERE id = v_part;

  INSERT INTO shipment_items(id, tenant_id, shipment_id, part_id)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, UUID_TO_BIN(p_shipment_uuid,1), v_part);

  INSERT INTO stock_ledger(tenant_id, part_id, from_type, to_type, qty, reason, ref_table, ref_id)
  SELECT tenant_id, id, 'PLANT','IN_TRANSIT',1,'SHIPMENT_OUT','shipments', p_shipment_uuid FROM parts WHERE id=v_part;
END$$
DELIMITER ;

-- Mark shipment delivered (moves parts to destination location)
DROP PROCEDURE IF EXISTS p_deliver_shipment;
DELIMITER $$
CREATE PROCEDURE p_deliver_shipment(
  IN p_shipment_uuid CHAR(36)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_ship BINARY(16) DEFAULT UUID_TO_BIN(p_shipment_uuid,1);
  DECLARE v_to_type ENUM('WAREHOUSE','PLANT','CUSTOMER');
  DECLARE v_to_id BINARY(16);
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();

  SELECT to_type, to_id INTO v_to_type, v_to_id FROM shipments WHERE id = v_ship;

  UPDATE shipments SET status='DELIVERED' WHERE id = v_ship;

  UPDATE parts p
  JOIN shipment_items si ON si.part_id = p.id AND si.shipment_id = v_ship
  SET p.status = 'IN_WAREHOUSE',
      p.current_location_type = IF(v_to_type='CUSTOMER','WAREHOUSE', v_to_type),
      p.current_location_id = IF(v_to_type='CUSTOMER', NULL, v_to_id);

  INSERT INTO stock_ledger(tenant_id, part_id, from_type, from_id, to_type, to_id, qty, reason, ref_table, ref_id)
  SELECT v_tenant, p.id, 'IN_TRANSIT', NULL,
         IF(v_to_type='CUSTOMER','WAREHOUSE', v_to_type),
         IF(v_to_type='CUSTOMER', NULL, v_to_id),
         1, 'SHIPMENT_IN', 'shipments', BIN_TO_UUID(v_ship,1)
  FROM parts p JOIN shipment_items si ON si.part_id=p.id AND si.shipment_id=v_ship;
END$$
DELIMITER ;

-- Record GPS event for leg
DROP PROCEDURE IF EXISTS p_leg_gps;
DELIMITER $$
CREATE PROCEDURE p_leg_gps(
  IN p_leg_uuid CHAR(36),
  IN p_ts TIMESTAMP(6),
  IN p_lat DECIMAL(9,6),
  IN p_lon DECIMAL(9,6),
  IN p_speed DECIMAL(8,2),
  IN p_heading DECIMAL(6,2)
)
SQL SECURITY DEFINER
BEGIN
  INSERT INTO leg_gps_events(tenant_id, leg_id, ts, lat, lon, speed_kmh, heading_deg)
  VALUES (security_get_tenant(), UUID_TO_BIN(p_leg_uuid,1), p_ts, p_lat, p_lon, p_speed, p_heading);
END$$
DELIMITER ;

-- Register vehicle
DROP PROCEDURE IF EXISTS p_register_vehicle;
DELIMITER $$
CREATE PROCEDURE p_register_vehicle(
  IN p_vin CHAR(17),
  IN p_make VARCHAR(80),
  IN p_model VARCHAR(80),
  IN p_year SMALLINT,
  IN p_trim VARCHAR(80)
)
SQL SECURITY DEFINER
BEGIN
  INSERT INTO vehicles(vin, tenant_id, make, model, year, trim)
  VALUES (p_vin, security_get_tenant(), p_make, p_model, p_year, p_trim)
  ON DUPLICATE KEY UPDATE make=VALUES(make), model=VALUES(model), year=VALUES(year), trim=VALUES(trim);
END$$
DELIMITER ;

-- Install part on vehicle
DROP PROCEDURE IF EXISTS p_install_part;
DELIMITER $$
CREATE PROCEDURE p_install_part(
  IN p_part_uuid CHAR(36),
  IN p_vin CHAR(17),
  IN p_position VARCHAR(80)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_tenant BINARY(16) DEFAULT security_get_tenant();
  DECLARE v_part BINARY(16) DEFAULT UUID_TO_BIN(p_part_uuid,1);

  UPDATE parts SET status='INSTALLED', current_location_type='VEHICLE', current_location_id=NULL
  WHERE id=v_part;

  INSERT INTO installations(id, tenant_id, part_id, vin, position)
  VALUES (UUID_TO_BIN(UUID(),1), v_tenant, v_part, p_vin, p_position);

  INSERT INTO stock_ledger(tenant_id, part_id, from_type, to_type, qty, reason, ref_table, ref_id)
  SELECT v_tenant, v_part, 'WAREHOUSE', 'VEHICLE', 1, 'INSTALL', 'installations',
         (SELECT BIN_TO_UUID(id,1) FROM installations WHERE part_id=v_part ORDER BY installed_at DESC LIMIT 1);
END$$
DELIMITER ;

-- Remove part from vehicle
DROP PROCEDURE IF EXISTS p_remove_part;
DELIMITER $$
CREATE PROCEDURE p_remove_part(
  IN p_part_uuid CHAR(36),
  IN p_reason VARCHAR(200)
)
SQL SECURITY DEFINER
BEGIN
  DECLARE v_part BINARY(16) DEFAULT UUID_TO_BIN(p_part_uuid,1);
  UPDATE installations SET removed_at=NOW(), removal_reason=p_reason
  WHERE part_id=v_part AND removed_at IS NULL;

  UPDATE parts SET status='RETURNED', current_location_type='WAREHOUSE', current_location_id=NULL
  WHERE id=v_part;

  INSERT INTO stock_ledger(tenant_id, part_id, from_type, to_type, qty, reason, ref_table, ref_id)
  SELECT tenant_id, v_part, 'VEHICLE','WAREHOUSE',1,'REMOVE','installations',
         (SELECT BIN_TO_UUID(id,1) FROM installations WHERE part_id=v_part ORDER BY installed_at DESC LIMIT 1)
  FROM parts WHERE id=v_part;
END$$
DELIMITER ;

-- ---------- GRANTS (read via views, write via procs) ----------
-- Adjust host pattern to match your users; keep EXECUTE/SELECT principle.
GRANT SELECT ON securedb.v_part_models TO 'app_user'@'%';
GRANT SELECT ON securedb.v_parts TO 'app_user'@'%';
GRANT SELECT ON securedb.v_shipments TO 'app_user'@'%';
GRANT SELECT ON securedb.v_installations TO 'app_user'@'%';
GRANT SELECT ON securedb.v_replacements TO 'app_user'@'%';

GRANT EXECUTE ON PROCEDURE securedb.security_set_tenant TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_create_oem TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_create_site TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_create_warehouse TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_register_part_model TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_mark_replacement TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_create_batch TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_generate_serials TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_qc_set TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_create_shipment TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_add_leg TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_add_shipment_item TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_deliver_shipment TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_leg_gps TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_register_vehicle TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_install_part TO 'app_user'@'%';
GRANT EXECUTE ON PROCEDURE securedb.p_remove_part TO 'app_user'@'%';

-- ---------- DEMO SEED (realistic walkthrough) ----------
-- Switch to demo tenant
CALL security_set_tenant('11111111-1111-4111-8111-111111111111');

-- OEM + site + warehouse + carrier
CALL p_create_oem('DMJ Components', 'IN');
-- capture OEM UUID for seeding (demo lookup)
SET @oem_id = (SELECT BIN_TO_UUID(id,1) FROM oems WHERE name='DMJ Components' AND tenant_id=security_get_tenant() LIMIT 1);

CALL p_create_site(@oem_id,'PLT-BLR-01','Bengaluru Plant','Bengaluru, KA, IN',12.9716,77.5946);
SET @site_id = (SELECT BIN_TO_UUID(id,1) FROM manufacturing_sites WHERE code='PLT-BLR-01' AND tenant_id=security_get_tenant());

CALL p_create_warehouse('WH-PUN-01','Pune DC','Pune, MH, IN',18.5204,73.8567);
SET @wh_id = (SELECT BIN_TO_UUID(id,1) FROM warehouses WHERE code='WH-PUN-01' AND tenant_id=security_get_tenant());

INSERT INTO carriers(id, tenant_id, name, mode, contact)
VALUES (UUID_TO_BIN(UUID(),1), security_get_tenant(), 'BlueTruck Logistics','TRUCK', JSON_OBJECT('phone','+91-202555000','email','ops@bt.example'));

SET @carrier_id = (SELECT BIN_TO_UUID(id,1) FROM carriers WHERE name='BlueTruck Logistics' AND tenant_id=security_get_tenant());

-- Part models
CALL p_register_part_model(@oem_id,'BRK-1001-A','Front Brake Pad A','BRAKE',
  JSON_OBJECT('material','ceramic','dimensions',JSON_OBJECT('w',150,'h',60,'t',12)), 60000, 36);

CALL p_register_part_model(@oem_id,'BRK-1001-B','Front Brake Pad B','BRAKE',
  JSON_OBJECT('material','semi-metallic','dimensions',JSON_OBJECT('w',150,'h',60,'t',12)), 50000, 30);

SET @model_a = (SELECT BIN_TO_UUID(id,1) FROM part_models WHERE sku='BRK-1001-A' AND tenant_id=security_get_tenant());
SET @model_b = (SELECT BIN_TO_UUID(id,1) FROM part_models WHERE sku='BRK-1001-B' AND tenant_id=security_get_tenant());

CALL p_mark_replacement(@model_a, @model_b, 'AFTERMARKET_EQUIV','2025-01-01', NULL, 'B is acceptable aftermarket replacement for A');

-- Batch + serials
CALL p_create_batch(@model_a, @site_id, 'LOT-2025-08-001', '2025-08-01', 10);
SET @batch_id = (SELECT BIN_TO_UUID(id,1) FROM part_batches WHERE lot_no='LOT-2025-08-001' AND tenant_id=security_get_tenant());
CALL p_generate_serials(@batch_id, 'A25BRK', 10);

-- QC pass 8, fail 2
SET @serials := (SELECT JSON_ARRAYAGG(BIN_TO_UUID(id,1)) FROM parts WHERE batch_id=UUID_TO_BIN(@batch_id,1));
-- pass first 8
SET @i=1;
WHILE @i<=8 DO
  CALL p_qc_set(JSON_EXTRACT(@serials, CONCAT('$[',@i-1,']')), 'PASS');
  SET @i=@i+1;
END WHILE;
-- fail remaining 2
WHILE @i<=10 DO
  CALL p_qc_set(JSON_EXTRACT(@serials, CONCAT('$[',@i-1,']')), 'FAIL');
  SET @i=@i+1;
END WHILE;

-- Shipment plant -> warehouse
CALL p_create_shipment('PLANT', @site_id, 'WAREHOUSE', @wh_id);
SET @ship_id = (SELECT BIN_TO_UUID(id,1) FROM shipments WHERE status='PLANNED' ORDER BY created_at DESC LIMIT 1);

CALL p_add_leg(@ship_id,1,@carrier_id,'TRUCK','2025-08-05 09:00:00','2025-08-06 18:00:00');

-- Add 6 QC_PASS parts to the shipment
SET @pass_serials := (SELECT JSON_ARRAYAGG(BIN_TO_UUID(id,1)) FROM parts WHERE status='QC_PASS' ORDER BY manufactured_at LIMIT 6);
SET @i=1;
WHILE @i<=6 DO
  CALL p_add_shipment_item(@ship_id, JSON_EXTRACT(@pass_serials, CONCAT('$[',@i-1,']')));
  SET @i=@i+1;
END WHILE;

-- GPS events during transit
SET @leg_id = (SELECT BIN_TO_UUID(id,1) FROM shipment_legs WHERE shipment_id=UUID_TO_BIN(@ship_id,1) AND seq=1);
CALL p_leg_gps(@leg_id, '2025-08-05 10:00:00.000000', 13.3392,77.1135, 60.5, 35.0);
CALL p_leg_gps(@leg_id, '2025-08-05 14:00:00.000000', 16.0667,75.5167, 65.2, 18.0);
CALL p_leg_gps(@leg_id, '2025-08-06 11:30:00.000000', 18.5204,73.8567, 28.0, 2.0);

-- Deliver shipment (parts move to warehouse)
CALL p_deliver_shipment(@ship_id);

-- Vehicle + install two parts
CALL p_register_vehicle('MA1AA1AA1AA123456','DMJ','Falcon','2025','Signature');
SET @part1 = JSON_EXTRACT(@pass_serials,'$[0]');
SET @part2 = JSON_EXTRACT(@pass_serials,'$[1]');
CALL p_install_part(@part1,'MA1AA1AA1AA123456','BRAKE-FRONT-LEFT');
CALL p_install_part(@part2,'MA1AA1AA1AA123456','BRAKE-FRONT-RIGHT');

-- ---------- DEMO QUERIES (read via views) ----------
-- SELECT * FROM v_part_models;
-- SELECT * FROM v_parts;
-- SELECT * FROM v_shipments;
-- SELECT * FROM v_installations;
-- SELECT * FROM v_replacements;

-- Done.
