
CREATE SCHEMA IF NOT EXISTS wrenidm AUTHORIZATION wrenidm;

-- -----------------------------------------------------
-- Table wrenidm.objecttpyes
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.objecttypes (
  id BIGSERIAL NOT NULL,
  objecttype VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (id),
  CONSTRAINT idx_objecttypes_objecttype UNIQUE (objecttype)
);

-- -----------------------------------------------------
-- Table wrenidm.genericobjects
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.genericobjects (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_genericobjects_objecttypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT idx_genericobjects_object UNIQUE (objecttypes_id, objectid)
);



-- -----------------------------------------------------
-- Table wrenidm.genericobjectproperties
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.genericobjectproperties (
  genericobjects_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(32) DEFAULT NULL,
  propvalue VARCHAR(65535), --H2 cannot create indexes on clobs yet (1.4.200)
  CONSTRAINT fk_genericobjectproperties_genericobjects FOREIGN KEY (genericobjects_id) REFERENCES wrenidm.genericobjects (id) ON DELETE CASCADE ON UPDATE NO ACTION
);
CREATE INDEX IF NOT EXISTS fk_genericobjectproperties_genericobjects ON wrenidm.genericobjectproperties (genericobjects_id);
CREATE INDEX IF NOT EXISTS idx_genericobjectproperties_prop ON wrenidm.genericobjectproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Table wrenidm.managedobjects
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.managedobjects (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_managedobjects_objectypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_managedobjects_object ON wrenidm.managedobjects (objecttypes_id,objectid);

-- -----------------------------------------------------
-- Table wrenidm.managedobjectproperties
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.managedobjectproperties (
  managedobjects_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(32) DEFAULT NULL,
  propvalue VARCHAR(65535),
  CONSTRAINT fk_managedobjectproperties_managedobjects FOREIGN KEY (managedobjects_id) REFERENCES wrenidm.managedobjects (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX IF NOT EXISTS fk_managedobjectproperties_managedobjects ON wrenidm.managedobjectproperties (managedobjects_id);
CREATE INDEX IF NOT EXISTS idx_managedobjectproperties_prop ON wrenidm.managedobjectproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Table wrenidm.configobjects
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.configobjects (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_configobjects_objecttypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_configobjects_object ON wrenidm.configobjects (objecttypes_id,objectid);
CREATE INDEX IF NOT EXISTS fk_configobjects_objecttypes ON wrenidm.configobjects (objecttypes_id);

-- -----------------------------------------------------
-- Table wrenidm.configobjectproperties
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.configobjectproperties (
  configobjects_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(255) DEFAULT NULL,
  propvalue VARCHAR(65535),
  CONSTRAINT fk_configobjectproperties_configobjects FOREIGN KEY (configobjects_id) REFERENCES wrenidm.configobjects (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX IF NOT EXISTS fk_configobjectproperties_configobjects ON wrenidm.configobjectproperties (configobjects_id);
CREATE INDEX IF NOT EXISTS idx_configobjectproperties_prop ON wrenidm.configobjectproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Table wrenidm.relationships
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.relationships (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_relationships_objecttypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT idx_relationships_object UNIQUE (objecttypes_id, objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.relationshipproperties (not used in postgres)
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.relationshipproperties (
  relationships_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(32) DEFAULT NULL,
  propvalue VARCHAR(65535),
  CONSTRAINT fk_relationshipproperties_relationships FOREIGN KEY (relationships_id) REFERENCES wrenidm.relationships (id) ON DELETE CASCADE ON UPDATE NO ACTION
);
CREATE INDEX IF NOT EXISTS fk_relationshipproperties_relationships ON wrenidm.relationshipproperties (relationships_id);
CREATE INDEX IF NOT EXISTS idx_relationshipproperties_prop ON wrenidm.relationshipproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Table wrenidm.links
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.links (
  objectid VARCHAR(38) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  linktype VARCHAR(50) NOT NULL,
  linkqualifier VARCHAR(50) NOT NULL,
  firstid VARCHAR(255) NOT NULL,
  secondid VARCHAR(255) NOT NULL,
  PRIMARY KEY (objectid)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_links_first ON wrenidm.links (linktype, linkqualifier, firstid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_links_second ON wrenidm.links (linktype, linkqualifier, secondid);

CREATE TABLE IF NOT EXISTS wrenidm.testobject (
  objectid VARCHAR(38) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  val VARCHAR(50) NOT NULL,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.securitykeys
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.securitykeys (
  objectid VARCHAR(38) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  keypair TEXT,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.auditauthentication
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS wrenidm.auditauthentication (
  objectid VARCHAR(56) NOT NULL,
  transactionid VARCHAR(255) NOT NULL,
  activitydate VARCHAR(29) NOT NULL,
  userid VARCHAR(255) DEFAULT NULL,
  eventname VARCHAR(50) DEFAULT NULL,
  result VARCHAR(255) DEFAULT NULL,
  principals TEXT,
  context TEXT,
  entries TEXT,
  trackingids TEXT,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.auditaccess
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.auditaccess (
  objectid VARCHAR(56) NOT NULL,
  activitydate VARCHAR(29) NOT NULL,
  eventname VARCHAR(255),
  transactionid VARCHAR(255) NOT NULL,
  userid VARCHAR(255) DEFAULT NULL,
  trackingids TEXT,
  server_ip VARCHAR(40),
  server_port VARCHAR(5),
  client_ip VARCHAR(40),
  client_port VARCHAR(5),
  request_protocol VARCHAR(255) NULL ,
  request_operation VARCHAR(255) NULL ,
  request_detail TEXT NULL ,
  http_request_secure VARCHAR(255) NULL ,
  http_request_method VARCHAR(255) NULL ,
  http_request_path VARCHAR(255) NULL ,
  http_request_queryparameters TEXT NULL ,
  http_request_headers TEXT NULL ,
  http_request_cookies TEXT NULL ,
  http_response_headers TEXT NULL ,
  response_status VARCHAR(255) NULL ,
  response_statuscode VARCHAR(255) NULL ,
  response_elapsedtime VARCHAR(255) NULL ,
  response_elapsedtimeunits VARCHAR(255) NULL ,
  response_detail TEXT NULL ,
  roles TEXT NULL ,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.auditconfig
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.auditconfig (
  objectid VARCHAR(56) NOT NULL,
  activitydate VARCHAR(29) NOT NULL,
  eventname VARCHAR(255) DEFAULT NULL,
  transactionid VARCHAR(255) NOT NULL,
  userid VARCHAR(255) DEFAULT NULL,
  trackingids TEXT,
  runas VARCHAR(255) DEFAULT NULL,
  configobjectid VARCHAR(255) NULL ,
  operation VARCHAR(255) NULL ,
  beforeObject TEXT,
  afterObject TEXT,
  changedfields TEXT DEFAULT NULL,
  rev VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.auditactivity
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.auditactivity (
  objectid VARCHAR(56) NOT NULL,
  activitydate VARCHAR(29) NOT NULL,
  eventname VARCHAR(255) DEFAULT NULL,
  transactionid VARCHAR(255) NOT NULL,
  userid VARCHAR(255) DEFAULT NULL,
  trackingids TEXT,
  runas VARCHAR(255) DEFAULT NULL,
  activityobjectid VARCHAR(255) NULL ,
  operation VARCHAR(255) NULL ,
  subjectbefore TEXT,
  subjectafter TEXT,
  changedfields TEXT DEFAULT NULL,
  subjectrev VARCHAR(255) DEFAULT NULL,
  passwordchanged VARCHAR(5) DEFAULT NULL,
  message TEXT,
  status VARCHAR(20),
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.auditrecon
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.auditrecon (
  objectid VARCHAR(56) NOT NULL,
  transactionid VARCHAR(255) NOT NULL,
  activitydate VARCHAR(29) NOT NULL,
  eventname VARCHAR(50) DEFAULT NULL,
  userid VARCHAR(255) DEFAULT NULL,
  trackingids TEXT,
  activity VARCHAR(24) DEFAULT NULL,
  exceptiondetail TEXT,
  linkqualifier VARCHAR(255) DEFAULT NULL,
  mapping VARCHAR(511) DEFAULT NULL,
  message TEXT,
  messagedetail TEXT,
  situation VARCHAR(24) DEFAULT NULL,
  sourceobjectid VARCHAR(511) DEFAULT NULL,
  status VARCHAR(20) DEFAULT NULL,
  targetobjectid VARCHAR(511) DEFAULT NULL,
  reconciling VARCHAR(12) DEFAULT NULL,
  ambiguoustargetobjectids TEXT,
  reconaction VARCHAR(36) DEFAULT NULL,
  entrytype VARCHAR(7) DEFAULT NULL,
  reconid VARCHAR(56) DEFAULT NULL,
  PRIMARY KEY (objectid)
);

CREATE INDEX IF NOT EXISTS idx_auditrecon_reconid ON wrenidm.auditrecon (reconid);
CREATE INDEX IF NOT EXISTS idx_auditrecon_entrytype ON wrenidm.auditrecon (entrytype);

-- -----------------------------------------------------
-- Table wrenidm.auditsync
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.auditsync (
  objectid VARCHAR(56) NOT NULL,
  transactionid VARCHAR(255) NOT NULL,
  activitydate VARCHAR(29) NOT NULL,
  eventname VARCHAR(50) DEFAULT NULL,
  userid VARCHAR(255) DEFAULT NULL,
  trackingids TEXT,
  activity VARCHAR(24) DEFAULT NULL,
  exceptiondetail TEXT,
  linkqualifier VARCHAR(255) DEFAULT NULL,
  mapping VARCHAR(511) DEFAULT NULL,
  message TEXT,
  messagedetail TEXT,
  situation VARCHAR(24) DEFAULT NULL,
  sourceobjectid VARCHAR(511) DEFAULT NULL,
  status VARCHAR(20) DEFAULT NULL,
  targetobjectid VARCHAR(511) DEFAULT NULL,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.internaluser
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.internaluser (
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  pwd VARCHAR(510) DEFAULT NULL,
  roles VARCHAR(1024) DEFAULT NULL,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.internalrole
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.internalrole (
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  description VARCHAR(510) DEFAULT NULL,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.schedulerobjects
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS wrenidm.schedulerobjects (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_schedulerobjects_objectypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_schedulerobjects_object ON wrenidm.schedulerobjects (objecttypes_id,objectid);
CREATE INDEX IF NOT EXISTS fk_schedulerobjects_objectypes ON wrenidm.schedulerobjects (objecttypes_id);

-- -----------------------------------------------------
-- Table wrenidm.schedulerobjectproperties
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS wrenidm.schedulerobjectproperties (
  schedulerobjects_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(32) DEFAULT NULL,
  propvalue VARCHAR(65535),
  CONSTRAINT fk_schedulerobjectproperties_schedulerobjects FOREIGN KEY (schedulerobjects_id) REFERENCES wrenidm.schedulerobjects (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX IF NOT EXISTS fk_schedulerobjectproperties_schedulerobjects ON wrenidm.schedulerobjectproperties (schedulerobjects_id);
CREATE INDEX IF NOT EXISTS idx_schedulerobjectproperties_prop ON wrenidm.schedulerobjectproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Table wrenidm.uinotification
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS wrenidm.uinotification (
  objectid VARCHAR(38) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  notificationType VARCHAR(255) NOT NULL,
  createDate VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  requester VARCHAR(255) NULL,
  receiverId VARCHAR(38) NOT NULL,
  requesterId VARCHAR(38) NULL,
  notificationSubtype VARCHAR(255) NULL,
  PRIMARY KEY (objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.clusterobjects
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS wrenidm.clusterobjects (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_clusterobjects_objectypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_clusterobjects_object ON wrenidm.clusterobjects (objecttypes_id,objectid);
CREATE INDEX IF NOT EXISTS fk_clusterobjects_objectypes ON wrenidm.clusterobjects (objecttypes_id);

-- -----------------------------------------------------
-- Table wrenidm.clusterobjectproperties
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS wrenidm.clusterobjectproperties (
  clusterobjects_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(32) DEFAULT NULL,
  propvalue VARCHAR(65535),
  CONSTRAINT fk_clusterobjectproperties_clusterobjects FOREIGN KEY (clusterobjects_id) REFERENCES wrenidm.clusterobjects (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX IF NOT EXISTS fk_clusterobjectproperties_clusterobjects ON wrenidm.clusterobjectproperties (clusterobjects_id);
CREATE INDEX IF NOT EXISTS idx_clusterobjectproperties_prop ON wrenidm.clusterobjectproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Table wrenidm.updateobjects
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.updateobjects (
  id BIGSERIAL NOT NULL,
  objecttypes_id BIGINT NOT NULL,
  objectid VARCHAR(255) NOT NULL,
  rev VARCHAR(38) NOT NULL,
  fullobject JSON,
  PRIMARY KEY (id),
  CONSTRAINT fk_updateobjects_objecttypes FOREIGN KEY (objecttypes_id) REFERENCES wrenidm.objecttypes (id) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT idx_updateobjects_object UNIQUE (objecttypes_id, objectid)
);

-- -----------------------------------------------------
-- Table wrenidm.updateobjectproperties
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS wrenidm.updateobjectproperties (
  updateobjects_id BIGINT NOT NULL,
  propkey VARCHAR(255) NOT NULL,
  proptype VARCHAR(32) DEFAULT NULL,
  propvalue VARCHAR(65535),
  CONSTRAINT fk_updateobjectproperties_updateobjects FOREIGN KEY (updateobjects_id) REFERENCES wrenidm.updateobjects (id) ON DELETE CASCADE ON UPDATE NO ACTION
);
CREATE INDEX IF NOT EXISTS fk_updateobjectproperties_updateobjects ON wrenidm.updateobjectproperties (updateobjects_id);
CREATE INDEX IF NOT EXISTS idx_updateobjectproperties_prop ON wrenidm.updateobjectproperties (propkey,propvalue);

-- -----------------------------------------------------
-- Data for table wrenidm.internaluser
-- -----------------------------------------------------
SAVEPOINT TRANSACTION;

MERGE INTO wrenidm.internaluser AS target
    USING (VALUES ('openidm-admin', '0', 'openidm-admin', '[ { "_ref" : "repo/internal/role/openidm-admin" }, { "_ref" : "repo/internal/role/openidm-authorized" } ]'),
            ('anonymous', '0', 'anonymous', '[ { "_ref" : "repo/internal/role/openidm-reg" } ]')) AS source
ON (source.C1=target.objectid)
    WHEN NOT MATCHED
        THEN INSERT(objectid, rev, pwd, roles)
            VALUES(source.C1, source.C2, source.C3, source.C4);

MERGE INTO wrenidm.internalrole AS target
    USING (VALUES ('openidm-authorized', '0', 'Basic minimum user'),
        ('openidm-admin', '0', 'Administrative access'),
        ('openidm-cert', '0', 'Authenticated via certificate'),
        ('openidm-tasks-manager', '0', 'Allowed to reassign workflow tasks'),
        ('openidm-reg', '0', 'Anonymous access')) AS source
ON (source.C1=target.objectid)
    WHEN NOT MATCHED
        THEN INSERT(objectid, rev, description)
            VALUES(source.C1, source.C2, source.C3);

COMMIT;
