-- =========================================================================
-- =========================================================================
-- Licensed to Qualys, Inc. (QUALYS) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- QUALYS licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-- =========================================================================
-- =========================================================================
--
-- This is an example IronBee lua module using the new FFI interface.
--
-- Author: Brian Rectanus <brectanus@qualys.com>
-- =========================================================================


-- ===============================================
-- Define local aliases of any globals to be used.
-- ===============================================
local base = _G
local ironbee = require("ironbee-ffi")

-- ===============================================
-- Declare the rest of the file as a module and
-- register the module table with ironbee.
-- ===============================================
module(...)
_COPYRIGHT = "Copyright (C) 2010-2011 Qualys, Inc."
_DESCRIPTION = "IronBee example DebugLog module"
_VERSION = "0.1"

-- ===============================================
-- This is called when the module loads
--
-- ib: IronBee engine handle
-- ===============================================
function onModuleLoad(ib)
    ironbee.ib_log_debug(ib, 0, "TestLogLevel 0 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 1, "TestLogLevel 1 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 2, "TestLogLevel 2 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 3, "TestLogLevel 3 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 4, "TestLogLevel 4 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 5, "TestLogLevel 5 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 6, "TestLogLevel 6 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 7, "TestLogLevel 7 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 8, "TestLogLevel 8 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 9, "TestLogLevel 9 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    ironbee.ib_log_debug(ib, 10, "TestLogLevel 10 %s.onModuleLoad ib=%p",
                       _NAME, ib.cvalue())
    return 0
end
