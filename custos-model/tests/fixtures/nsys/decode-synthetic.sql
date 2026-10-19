-- SYNTHETIC nsys SQLite export (hand-built, not a capture).
-- Schema: the documented Nsight Systems export schema, EXPORT_SCHEMA_VERSION
-- 3.20.3 (Nsight Systems 2025.3.2 User Guide, "SQLite Schema Reference"); only
-- the tables the Custos adapter reads, with every documented column. Rows are
-- invented to exercise the adapter: one GPU, five launches of one decode-like
-- kernel from one CPU thread with host gaps between them, one host-to-device
-- copy, one memset, the CUDA API calls behind them, and one OS runtime call.
-- Timestamps are ns from capture start. Replace with a real capture
-- (tools/capture_fixtures.sh) when one exists; the tests then change to it.
CREATE TABLE StringIds (
    id                          INTEGER   NOT NULL   PRIMARY KEY,
    value                       TEXT      NOT NULL
);
CREATE TABLE ThreadNames (
    nameId                      INTEGER   NOT NULL,
    priority                    INTEGER,
    globalTid                   INTEGER
);
CREATE TABLE META_DATA_EXPORT (
    name                        TEXT      NOT NULL,
    value                       TEXT
);
CREATE TABLE META_DATA_CAPTURE (
    name                        TEXT      NOT NULL,
    value                       TEXT
);
CREATE TABLE TARGET_INFO_GPU (
    vmId                        INTEGER   NOT NULL,
    id                          INTEGER   NOT NULL,
    name                        TEXT,
    busLocation                 TEXT,
    isDiscrete                  INTEGER,
    l2CacheSize                 INTEGER,
    totalMemory                 INTEGER,
    memoryBandwidth             INTEGER,
    clockRate                   INTEGER,
    smCount                     INTEGER,
    pwGpuId                     INTEGER,
    uuid                        TEXT,
    luid                        INTEGER,
    chipName                    TEXT,
    cuDevice                    INTEGER,
    ctxswDevPath                TEXT,
    ctrlDevPath                 TEXT,
    revision                    INTEGER,
    nodeMask                    INTEGER,
    constantMemory              INTEGER,
    maxIPC                      INTEGER,
    maxRegistersPerBlock        INTEGER,
    maxShmemPerBlock            INTEGER,
    maxShmemPerBlockOptin       INTEGER,
    maxShmemPerSm               INTEGER,
    maxRegistersPerSm           INTEGER,
    threadsPerWarp              INTEGER,
    asyncEngines                INTEGER,
    maxWarpsPerSm               INTEGER,
    maxBlocksPerSm              INTEGER,
    maxThreadsPerBlock          INTEGER,
    maxBlockDimX                INTEGER,
    maxBlockDimY                INTEGER,
    maxBlockDimZ                INTEGER,
    maxGridDimX                 INTEGER,
    maxGridDimY                 INTEGER,
    maxGridDimZ                 INTEGER,
    computeMajor                INTEGER,
    computeMinor                INTEGER,
    smMajor                     INTEGER,
    smMinor                     INTEGER
);
CREATE TABLE ENUM_CUDA_MEMCPY_OPER (
    id                          INTEGER   NOT NULL   PRIMARY KEY,
    name                        TEXT,
    label                       TEXT
);
CREATE TABLE ENUM_CUDA_MEM_KIND (
    id                          INTEGER   NOT NULL   PRIMARY KEY,
    name                        TEXT,
    label                       TEXT
);
CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL (
    start                       INTEGER   NOT NULL,
    end                         INTEGER   NOT NULL,
    deviceId                    INTEGER   NOT NULL,
    contextId                   INTEGER   NOT NULL,
    greenContextId              INTEGER,
    streamId                    INTEGER   NOT NULL,
    correlationId               INTEGER,
    globalPid                   INTEGER,
    demangledName               INTEGER   NOT NULL,
    shortName                   INTEGER   NOT NULL,
    mangledName                 INTEGER,
    launchType                  INTEGER,
    cacheConfig                 INTEGER,
    registersPerThread          INTEGER   NOT NULL,
    gridX                       INTEGER   NOT NULL,
    gridY                       INTEGER   NOT NULL,
    gridZ                       INTEGER   NOT NULL,
    blockX                      INTEGER   NOT NULL,
    blockY                      INTEGER   NOT NULL,
    blockZ                      INTEGER   NOT NULL,
    staticSharedMemory          INTEGER   NOT NULL,
    dynamicSharedMemory         INTEGER   NOT NULL,
    localMemoryPerThread        INTEGER   NOT NULL,
    localMemoryTotal            INTEGER   NOT NULL,
    gridId                      INTEGER   NOT NULL,
    sharedMemoryExecuted        INTEGER,
    graphNodeId                 INTEGER,
    sharedMemoryLimitConfig     INTEGER
);
CREATE TABLE CUPTI_ACTIVITY_KIND_MEMCPY (
    start                       INTEGER   NOT NULL,
    end                         INTEGER   NOT NULL,
    deviceId                    INTEGER   NOT NULL,
    contextId                   INTEGER   NOT NULL,
    greenContextId              INTEGER,
    streamId                    INTEGER   NOT NULL,
    correlationId               INTEGER,
    globalPid                   INTEGER,
    bytes                       INTEGER   NOT NULL,
    copyKind                    INTEGER   NOT NULL,
    deprecatedSrcId             INTEGER,
    srcKind                     INTEGER,
    dstKind                     INTEGER,
    srcDeviceId                 INTEGER,
    srcContextId                INTEGER,
    dstDeviceId                 INTEGER,
    dstContextId                INTEGER,
    migrationCause              INTEGER,
    graphNodeId                 INTEGER,
    virtualAddress              INTEGER,
    copyCount                   INTEGER
);
CREATE TABLE CUPTI_ACTIVITY_KIND_MEMSET (
    start                       INTEGER   NOT NULL,
    end                         INTEGER   NOT NULL,
    deviceId                    INTEGER   NOT NULL,
    contextId                   INTEGER   NOT NULL,
    greenContextId              INTEGER,
    streamId                    INTEGER   NOT NULL,
    correlationId               INTEGER,
    globalPid                   INTEGER,
    value                       INTEGER   NOT NULL,
    bytes                       INTEGER   NOT NULL,
    graphNodeId                 INTEGER,
    memKind                     INTEGER
);
CREATE TABLE CUPTI_ACTIVITY_KIND_RUNTIME (
    start                       INTEGER   NOT NULL,
    end                         INTEGER   NOT NULL,
    eventClass                  INTEGER   NOT NULL,
    globalTid                   INTEGER,
    correlationId               INTEGER,
    nameId                      INTEGER   NOT NULL,
    returnValue                 INTEGER   NOT NULL,
    callchainId                 INTEGER
);
CREATE TABLE OSRT_API (
    start                       INTEGER   NOT NULL,
    end                         INTEGER   NOT NULL,
    eventClass                  INTEGER   NOT NULL,
    globalTid                   INTEGER,
    nameId                      INTEGER   NOT NULL,
    returnValue                 INTEGER   NOT NULL,
    nestingLevel                INTEGER,
    callchainId                 INTEGER   NOT NULL
);
CREATE TABLE TARGET_INFO_SESSION_START_TIME (
    utcEpochNs                  INTEGER,
    utcTime                     TEXT,
    localTime                   TEXT
);
INSERT INTO META_DATA_EXPORT (name, value) VALUES ('EXPORT_SCHEMA_VERSION', '3.20.3');
INSERT INTO TARGET_INFO_SESSION_START_TIME VALUES (1792310400000000000, '2026-10-18T00:00:00.000Z', NULL);
INSERT INTO StringIds (id, value) VALUES
  (1, 'void aegis::gemm::gemv_tc_kernel<aegis::gemm::DecTile<64, 64, 4, 0, 0>, 6>(aegis::gemm::KParams, aegis::gemm::TcArgs, bool)'),
  (2, 'gemv_tc_kernel'),
  (3, '_ZN5aegis4gemm14gemv_tc_kernelINS0_7DecTileILi64ELi64ELi4ELi0ELi0EEELi6EEEvNS0_7KParamsENS0_6TcArgsEb'),
  (4, 'cudaLaunchKernel_v7000'),
  (5, 'cudaMemcpyAsync_v3020'),
  (6, 'cudaMemsetAsync_v3020'),
  (7, 'cudaStreamSynchronize_v3020'),
  (8, 'pthread_cond_wait'),
  (9, 'bench');
INSERT INTO ThreadNames (nameId, priority, globalTid) VALUES (9, 0, 72057662757408769);
INSERT INTO TARGET_INFO_GPU (vmId, id, name, busLocation, isDiscrete, l2CacheSize, totalMemory, memoryBandwidth, clockRate, smCount, pwGpuId, uuid, luid, chipName, cuDevice, ctxswDevPath, ctrlDevPath, revision, nodeMask, constantMemory, maxIPC, maxRegistersPerBlock, maxShmemPerBlock, maxShmemPerBlockOptin, maxShmemPerSm, maxRegistersPerSm, threadsPerWarp, asyncEngines, maxWarpsPerSm, maxBlocksPerSm, maxThreadsPerBlock, maxBlockDimX, maxBlockDimY, maxBlockDimZ, maxGridDimX, maxGridDimY, maxGridDimZ, computeMajor, computeMinor, smMajor, smMinor)
  VALUES (0, 0, 'Synthetic GPU', NULL, 0, 25165824, NULL, NULL, 2418000000, 48, 0, NULL, NULL, 'GB10', 0, NULL, NULL, 0, 1, 65536, 4, 65536, 49152, 101376, 102400, 65536, 32, 2, 48, 24, 1024, 1024, 1024, 64, 2147483647, 65535, 65535, 12, 1, 12, 1);
INSERT INTO ENUM_CUDA_MEMCPY_OPER (id, name, label) VALUES (1, 'CUDA_MEMCPY_KIND_HTOD', 'Host-to-Device');
INSERT INTO ENUM_CUDA_MEM_KIND (id, name, label) VALUES (0, 'CUDA_MEMOPR_MEMORY_KIND_PAGEABLE', 'Pageable'), (2, 'CUDA_MEMOPR_MEMORY_KIND_DEVICE', 'Device');
-- CPU thread: pid 4096, tid 4097 (nsys reports decode globalTid as pid = (gtid >> 24) & 0xFFFFFF, tid = gtid & 0xFFFFFF).
INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME (start, end, eventClass, globalTid, correlationId, nameId, returnValue, callchainId) VALUES
  (1000000, 1012000, 1, 72057662757408769, 1, 5, 0, NULL),
  (1013000, 1015000, 1, 72057662757408769, 2, 6, 0, NULL),
  (1020000, 1023500, 1, 72057662757408769, 3, 4, 0, NULL),
  (1030000, 1033500, 1, 72057662757408769, 4, 4, 0, NULL),
  (1040000, 1043500, 1, 72057662757408769, 5, 4, 0, NULL),
  (1050000, 1053500, 1, 72057662757408769, 6, 4, 0, NULL),
  (1060000, 1063500, 1, 72057662757408769, 7, 4, 0, NULL),
  (1064000, 1080000, 1, 72057662757408769, 8, 7, 0, NULL);
INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY (start, end, deviceId, contextId, greenContextId, streamId, correlationId, globalPid, bytes, copyKind, deprecatedSrcId, srcKind, dstKind, srcDeviceId, srcContextId, dstDeviceId, dstContextId, migrationCause, graphNodeId, virtualAddress, copyCount)
  VALUES (1004000, 1011000, 0, 1, NULL, 13, 1, 72057662757404672, 8028160, 1, NULL, 0, 2, NULL, NULL, 0, 1, NULL, NULL, NULL, 1);
INSERT INTO CUPTI_ACTIVITY_KIND_MEMSET (start, end, deviceId, contextId, greenContextId, streamId, correlationId, globalPid, value, bytes, graphNodeId, memKind)
  VALUES (1014000, 1014800, 0, 1, NULL, 13, 2, 72057662757404672, 0, 3584, NULL, 2);
-- Five launches of one kernel: 9 us each on the GPU, 1 us apart; their launch calls are 10 us apart.
INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL (start, end, deviceId, contextId, greenContextId, streamId, correlationId, globalPid, demangledName, shortName, mangledName, launchType, cacheConfig, registersPerThread, gridX, gridY, gridZ, blockX, blockY, blockZ, staticSharedMemory, dynamicSharedMemory, localMemoryPerThread, localMemoryTotal, gridId, sharedMemoryExecuted, graphNodeId, sharedMemoryLimitConfig) VALUES
  (1025000, 1034000, 0, 1, NULL, 13, 3, 72057662757404672, 1, 2, 3, 0, 0, 70, 14, 1, 1, 128, 1, 1, 0, 49152, 0, 0, 101, 65536, NULL, NULL),
  (1035000, 1044000, 0, 1, NULL, 13, 4, 72057662757404672, 1, 2, 3, 0, 0, 70, 14, 1, 1, 128, 1, 1, 0, 49152, 0, 0, 102, 65536, NULL, NULL),
  (1045000, 1054000, 0, 1, NULL, 13, 5, 72057662757404672, 1, 2, 3, 0, 0, 70, 14, 1, 1, 128, 1, 1, 0, 49152, 0, 0, 103, 65536, NULL, NULL),
  (1055000, 1064000, 0, 1, NULL, 13, 6, 72057662757404672, 1, 2, 3, 0, 0, 70, 14, 1, 1, 128, 1, 1, 0, 49152, 0, 0, 104, 65536, NULL, NULL),
  (1065000, 1074000, 0, 1, NULL, 13, 7, 72057662757404672, 1, 2, 3, 0, 0, 70, 14, 1, 1, 128, 1, 1, 0, 49152, 0, 0, 105, 65536, NULL, NULL);
INSERT INTO OSRT_API (start, end, eventClass, globalTid, nameId, returnValue, nestingLevel, callchainId) VALUES
  (1064500, 1079500, 27, 72057662757408769, 8, 0, 0, 0);
