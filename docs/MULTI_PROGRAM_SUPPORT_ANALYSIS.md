# Multi-Program Support Analysis for MCP4GhidraPlugin.java

Generated: December 10, 2025

## Summary

- **Total Endpoints:** 127
- **Already Have programName Support:** 9
- **Need programName Support (READ):** ~70
- **Need programName Support (WRITE):** ~40
- **Should NOT have programName:** ~8

---

## ALREADY IMPLEMENTED (Have programName parameter)

These endpoints already support multi-program operations via the `program` query parameter:

| Endpoint | Handler Method | Line | Notes |
|----------|----------------|------|-------|
| `/list_functions` | `listFunctions(String programName)` | 259 | ✅ Complete |
| `/list_functions_enhanced` | `listFunctionsEnhanced(int, int, String programName)` | 266 | ✅ Complete |
| `/search_functions` | `searchFunctionsByName(String, int, int, String programName)` | 303 | ✅ Complete |
| `/search_functions_enhanced` | `searchFunctionsEnhanced(..., String programName)` | 1316 | ✅ Complete |
| `/decompile_function` | `decompileFunctionByAddress(String, String programName)` | 334 | ✅ Complete |
| `/disassemble_function` | `disassembleFunction(String, String programName)` | 341 | ✅ Complete |
| `/get_xrefs_to` | `getXrefsTo(String, int, int, String programName)` | 517 | ✅ Complete |
| `/get_xrefs_from` | `getXrefsFrom(String, int, int, String programName)` | 526 | ✅ Complete |
| `/get_function_xrefs` | `getFunctionXrefs(String, int, int, String programName)` | 535 | ✅ Complete |

---

## ENDPOINTS THAT SHOULD NOT HAVE programName

These are meta/UI endpoints that operate on Ghidra's current state, not a specific program:

| Endpoint | Handler Method | Line | Reason |
|----------|----------------|------|--------|
| `/get_current_address` | `getCurrentAddress()` | 322 | Returns UI cursor position |
| `/get_current_function` | `getCurrentFunction()` | 326 | Returns UI selection |
| `/get_current_program_info` | `getCurrentProgramInfo()` | 1399 | Returns active program info |
| `/list_open_programs` | `listOpenPrograms()` | 1393 | Lists all open programs |
| `/switch_program` | `switchProgram(String)` | 1405 | Changes active program |
| `/list_project_files` | `listProjectFiles(String)` | 1413 | Lists project contents |
| `/open_program` | `openProgramFromProject(String)` | 1421 | Opens a program |
| `/check_connection` | `checkConnection()` | 716 | Health check |
| `/get_version` | `getVersion()` | 720 | Version info |

---

## HIGH PRIORITY - READ ENDPOINTS NEEDING programName

Critical for cross-binary analysis and documentation propagation:

### Function Analysis Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/get_function_by_address` | `getFunctionByAddress(String)` | 316 | ❌ Uses `getCurrentProgram()` |
| `/get_function_callees` | `getFunctionCallees(String, int, int)` | 619 | ❌ Uses `getCurrentProgram()` (line 5788) |
| `/get_function_callers` | `getFunctionCallers(String, int, int)` | 627 | ❌ Uses `getCurrentProgram()` (line 5869) |
| `/get_function_call_graph` | `getFunctionCallGraph(String, int, String)` | 635 | ❌ Uses `getCurrentProgram()` (line 5940) |
| `/get_full_call_graph` | `getFullCallGraph(String, int)` | 643 | ❌ Uses `getCurrentProgram()` |
| `/get_function_labels` | `getFunctionLabels(String, int, int)` | 544 | ❌ Uses `getCurrentProgram()` |
| `/get_function_jump_targets` | `getFunctionJumpTargets(String, int, int)` | 552 | ❌ Uses `getCurrentProgram()` |
| `/get_function_variables` | `getFunctionVariables(String)` | 1132 | ❌ Uses `getCurrentProgram()` |
| `/get_function_hash` | `getFunctionHash(String)` | 1433 | ❌ Uses `getCurrentProgram()` |
| `/get_bulk_function_hashes` | `getBulkFunctionHashes(int, int, String)` | 1441 | ❌ Uses `getCurrentProgram()` |
| `/get_function_documentation` | `getFunctionDocumentation(String)` | 1451 | ❌ Uses `getCurrentProgram()` |
| `/analyze_function_completeness` | `analyzeFunctionCompleteness(String)` | 1175 | ❌ Uses `getCurrentProgram()` (line 1180) |
| `/analyze_function_complete` | `analyzeFunctionComplete(...)` | 1302 | ❌ Uses `getCurrentProgram()` |
| `/find_next_undefined_function` | `findNextUndefinedFunction(...)` | 1207 | ❌ Uses `getCurrentProgram()` |

### Data & Symbol Listing Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/list_methods` | `getAllFunctionNames(int, int)` | 202 | ❌ Uses `getCurrentProgram()` (line 1482) |
| `/list_classes` | `getAllClassNames(int, int)` | 209 | ❌ Uses `getCurrentProgram()` (line 1493) |
| `/list_segments` | `listSegments(int, int)` | 216 | ❌ Uses `getCurrentProgram()` (line 1510) |
| `/list_imports` | `listImports(int, int)` | 223 | ❌ Uses `getCurrentProgram()` (line 1521) |
| `/list_exports` | `listExports(int, int)` | 230 | ❌ Uses `getCurrentProgram()` (line 1532) |
| `/list_namespaces` | `listNamespaces(int, int)` | 237 | ❌ Uses `getCurrentProgram()` (line 1550) |
| `/list_data_items` | `listDefinedData(int, int)` | 244 | ❌ Uses `getCurrentProgram()` (line 1566) |
| `/list_data_items_by_xrefs` | `listDataItemsByXrefs(int, int, String)` | 251 | ❌ Uses `getCurrentProgram()` (line 1608) |
| `/list_globals` | `listGlobals(int, int, String)` | 735 | ❌ Uses `getCurrentProgram()` |
| `/list_strings` | `listDefinedStrings(int, int, String)` | 707 | ❌ Uses `getCurrentProgram()` (line 3621) |
| `/list_external_locations` | `listExternalLocations(int, int)` | 570 | ❌ Uses `getCurrentProgram()` |
| `/get_external_location` | `getExternalLocationDetails(String, String)` | 577 | ❌ Uses `getCurrentProgram()` |
| `/get_entry_points` | `getEntryPoints()` | 751 | ❌ Uses `getCurrentProgram()` |

### Data Type Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/list_data_types` | `listDataTypes(String, int, int)` | 654 | ❌ Uses `getCurrentProgram()` |
| `/get_type_size` | `getTypeSize(String)` | 776 | ❌ Uses `getCurrentProgram()` |
| `/get_struct_layout` | `getStructLayout(String)` | 782 | ❌ Uses `getCurrentProgram()` |
| `/search_data_types` | `searchDataTypes(String, int, int)` | 788 | ❌ Uses `getCurrentProgram()` |
| `/get_enum_values` | `getEnumValues(String)` | 796 | ❌ Uses `getCurrentProgram()` |
| `/list_data_type_categories` | `listDataTypeCategories(int, int)` | 887 | ❌ Uses `getCurrentProgram()` |
| `/get_valid_data_types` | `getValidDataTypes(String)` | 1156 | ❌ Uses `getCurrentProgram()` |
| `/validate_data_type` | `validateDataType(String, String)` | 1165 | ❌ Uses `getCurrentProgram()` |
| `/validate_data_type_exists` | `validateDataTypeExists(String)` | 1284 | ❌ Uses `getCurrentProgram()` |

### Memory & Xref Analysis Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/read_memory` | `readMemory(String, int)` | 905 | ❌ Uses `getCurrentProgram()` |
| `/get_bulk_xrefs` | `getBulkXrefs(Object)` | 918 | ❌ Uses `getCurrentProgram()` |
| `/analyze_data_region` | `analyzeDataRegion(...)` | 926 | ❌ Uses `getCurrentProgram()` |
| `/detect_array_bounds` | `detectArrayBounds(...)` | 940 | ❌ Uses `getCurrentProgram()` |
| `/get_assembly_context` | `getAssemblyContext(...)` | 952 | ❌ Uses `getCurrentProgram()` |
| `/analyze_struct_field_usage` | `analyzeStructFieldUsage(...)` | 978 | ❌ Uses `getCurrentProgram()` |
| `/get_field_access_context` | `getFieldAccessContext(...)` | 989 | ❌ Uses `getCurrentProgram()` |
| `/suggest_field_names` | `suggestFieldNames(...)` | 1000 | ❌ Uses `getCurrentProgram()` |
| `/inspect_memory_content` | `inspectMemoryContent(...)` | 1010 | ❌ Uses `getCurrentProgram()` |
| `/search_byte_patterns` | `searchBytePatterns(...)` | 1029 | ❌ Uses `getCurrentProgram()` |

### Metadata & Analysis Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/get_metadata` | `getMetadata()` | 724 | ❌ Uses `getCurrentProgram()` |
| `/list_calling_conventions` | `listCallingConventions()` | 394 | ❌ Uses `getCurrentProgram()` |
| `/can_rename_at_address` | `canRenameAtAddress(String)` | 1293 | ❌ Uses `getCurrentProgram()` |
| `/validate_function_prototype` | `validateFunctionPrototype(...)` | 1273 | ❌ Uses `getCurrentProgram()` |

### Malware/Security Analysis Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/detect_crypto_constants` | `detectCryptoConstants()` | 1023 | ❌ Uses `getCurrentProgram()` |
| `/find_similar_functions` | `findSimilarFunctions(...)` | 1039 | ❌ Uses `getCurrentProgram()` |
| `/analyze_control_flow` | `analyzeControlFlow(String)` | 1049 | ❌ Uses `getCurrentProgram()` |
| `/find_anti_analysis_techniques` | `findAntiAnalysisTechniques()` | 1058 | ❌ Uses `getCurrentProgram()` |
| `/batch_decompile` | `batchDecompileFunctions(String)` | 1064 | ❌ Uses `getCurrentProgram()` |
| `/find_dead_code` | `findDeadCode(String)` | 1073 | ❌ Uses `getCurrentProgram()` |
| `/decrypt_strings_auto` | `autoDecryptStrings()` | 1082 | ❌ Uses `getCurrentProgram()` |
| `/analyze_api_call_chains` | `analyzeAPICallChains()` | 1088 | ❌ Uses `getCurrentProgram()` |
| `/extract_iocs_with_context` | `extractIOCsWithContext()` | 1094 | ❌ Uses `getCurrentProgram()` |
| `/detect_malware_behaviors` | `detectMalwareBehaviors()` | 1100 | ❌ Uses `getCurrentProgram()` |

---

## MEDIUM PRIORITY - WRITE ENDPOINTS NEEDING programName

These modify program state - less critical but still useful for cross-binary work:

### Rename Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/rename_function` | `renameFunction(String, String)` | 278 | ❌ Uses `getCurrentProgram()` (line 1767) |
| `/rename_function_by_address` | `renameFunctionByAddress(String, String)` | 364 | ❌ Uses `getCurrentProgram()` |
| `/rename_data` | `renameDataAtAddress(String, String)` | 284 | ❌ Uses `getCurrentProgram()` |
| `/rename_variable` | `renameVariableInFunction(...)` | 290 | ❌ Uses `getCurrentProgram()` |
| `/rename_label` | `renameLabel(String, String, String)` | 560 | ❌ Uses `getCurrentProgram()` |
| `/rename_external_location` | `renameExternalLocation(String, String)` | 584 | ❌ Uses `getCurrentProgram()` |
| `/rename_global_variable` | `renameGlobalVariable(String, String)` | 743 | ❌ Uses `getCurrentProgram()` |
| `/rename_or_label` | `renameOrLabel(String, String)` | 607 | ❌ Uses `getCurrentProgram()` |
| `/batch_rename_function_components` | `batchRenameFunctionComponents(...)` | 1141 | ❌ Uses `getCurrentProgram()` |
| `/batch_rename_variables` | `batchRenameVariables(...)` | 1248 | ❌ Uses `getCurrentProgram()` |

### Comment Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/set_decompiler_comment` | `setDecompilerComment(String, String)` | 348 | ❌ Uses `getCurrentProgram()` |
| `/set_disassembly_comment` | `setDisassemblyComment(String, String)` | 356 | ❌ Uses `getCurrentProgram()` |
| `/set_plate_comment` | `setPlateComment(String, String)` | 1122 | ❌ Uses `getCurrentProgram()` |
| `/batch_set_comments` | `batchSetComments(...)` | 1108 | ❌ Uses `getCurrentProgram()` |

### Function Prototype Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/set_function_prototype` | `setFunctionPrototype(...)` | 372 | ❌ Uses `getCurrentProgram()` |
| `/set_local_variable_type` | `setLocalVariableType(...)` | 399 | ❌ Uses `getCurrentProgram()` |
| `/set_function_no_return` | `setFunctionNoReturn(String, boolean)` | 418 | ❌ Uses `getCurrentProgram()` |
| `/set_variable_storage` | `setVariableStorage(...)` | 452 | ❌ Uses `getCurrentProgram()` |
| `/batch_set_variable_types` | `batchSetVariableTypesOptimized(...)` | 1219 | ❌ Uses `getCurrentProgram()` |

### Data Type Modification Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/create_struct` | `createStruct(String, String)` | 662 | ❌ Uses `getCurrentProgram()` |
| `/create_enum` | `createEnum(String, String, int)` | 678 | ❌ Uses `getCurrentProgram()` |
| `/create_union` | `createUnion(String, String)` | 756 | ❌ Uses `getCurrentProgram()` |
| `/create_typedef` | `createTypedef(String, String)` | 802 | ❌ Uses `getCurrentProgram()` |
| `/create_array_type` | `createArrayType(...)` | 858 | ❌ Uses `getCurrentProgram()` |
| `/create_pointer_type` | `createPointerType(...)` | 867 | ❌ Uses `getCurrentProgram()` |
| `/clone_data_type` | `cloneDataType(...)` | 809 | ❌ Uses `getCurrentProgram()` |
| `/delete_data_type` | `deleteDataType(String)` | 826 | ❌ Uses `getCurrentProgram()` |
| `/apply_data_type` | `applyDataType(...)` | 697 | ❌ Uses `getCurrentProgram()` |
| `/modify_struct_field` | `modifyStructField(...)` | 832 | ❌ Uses `getCurrentProgram()` |
| `/add_struct_field` | `addStructField(...)` | 841 | ❌ Uses `getCurrentProgram()` |
| `/remove_struct_field` | `removeStructField(...)` | 851 | ❌ Uses `getCurrentProgram()` |
| `/create_data_type_category` | `createDataTypeCategory(String)` | 874 | ❌ Uses `getCurrentProgram()` |
| `/move_data_type_to_category` | `moveDataTypeToCategory(...)` | 880 | ❌ Uses `getCurrentProgram()` |
| `/create_function_signature` | `createFunctionSignature(...)` | 894 | ❌ Uses `getCurrentProgram()` |
| `/import_data_types` | `importDataTypes(...)` | 818 | ❌ Uses `getCurrentProgram()` |

### Label & Symbol Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/create_label` | `createLabel(String, String)` | 591 | ❌ Uses `getCurrentProgram()` |
| `/batch_create_labels` | `batchCreateLabels(List)` | 600 | ❌ Uses `getCurrentProgram()` |

### Bookmark Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/set_bookmark` | `setBookmark(...)` | 1360 | ❌ Uses `getCurrentProgram()` |
| `/list_bookmarks` | `listBookmarks(...)` | 1371 | ❌ Uses `getCurrentProgram()` |
| `/delete_bookmark` | `deleteBookmark(...)` | 1381 | ❌ Uses `getCurrentProgram()` |

### Other Write Endpoints

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/apply_data_classification` | `applyDataClassification(...)` | 963 | ❌ Uses `getCurrentProgram()` |
| `/force_decompile` | `forceDecompile(String)` | 500 | ❌ Uses `getCurrentProgram()` (line 3411) |
| `/clear_instruction_flow_override` | `clearInstructionFlowOverride(String)` | 438 | ❌ Uses `getCurrentProgram()` |
| `/apply_function_documentation` | `applyFunctionDocumentation(String)` | 1459 | ❌ Uses `getCurrentProgram()` |
| `/disassemble_bytes` | `disassembleBytes(...)` | 1335 | ❌ Uses `getCurrentProgram()` |

### Script Endpoints (Program Context Dependent)

| Endpoint | Handler Method | Line | Current Status |
|----------|----------------|------|----------------|
| `/run_script` | `runGhidraScript(...)` | 476 | Scripts run on current program |
| `/list_scripts` | `listGhidraScripts(String)` | 491 | No program context needed |
| `/run_ghidra_script` | `runGhidraScriptWithCapture(...)` | 1348 | Scripts run on current program |

---

## LOW PRIORITY - Utility Endpoints

These don't need programName as they're program-independent:

| Endpoint | Handler Method | Line | Notes |
|----------|----------------|------|-------|
| `/convert_number` | `convertNumber(String, int)` | 728 | Pure utility |
| `/list_scripts` | `listGhidraScripts(String)` | 491 | Lists available scripts |

---

## Implementation Pattern

The existing multi-program endpoints use this pattern:

```java
// In endpoint handler:
String programName = qparams.get("program");  // Optional: target specific program
sendResponse(exchange, someMethod(params, programName));

// In method implementation:
private String someMethod(String param, String programName) {
    Object[] result = getProgramOrError(programName);
    Program program = (Program) result[0];
    if (program == null) return (String) result[1];
    // ... rest of implementation using program instead of getCurrentProgram()
}
```

The `getProgramOrError(String programName)` method at line 4347 handles:
1. If programName is null/empty → returns `getCurrentProgram()`
2. Otherwise → finds the named program from open programs
3. Returns `Object[]{Program, ErrorString}` where one is null

---

## Recommended Implementation Order

### Phase 1: Core Read Operations (Critical for cross-binary analysis)
1. `get_function_by_address`
2. `get_function_callees`
3. `get_function_callers`
4. `get_function_call_graph`
5. `get_function_variables`
6. `get_function_hash`
7. `get_bulk_function_hashes`
8. `get_function_documentation`
9. `analyze_function_complete`
10. `analyze_function_completeness`

### Phase 2: Listing Operations
1. `list_methods`
2. `list_classes`
3. `list_segments`
4. `list_imports`
5. `list_exports`
6. `list_namespaces`
7. `list_data_items`
8. `list_globals`
9. `list_strings`
10. `list_data_types`

### Phase 3: Data Analysis
1. `read_memory`
2. `get_bulk_xrefs`
3. `analyze_data_region`
4. `get_metadata`

### Phase 4: Write Operations (As needed)
- Rename operations
- Comment operations
- Data type modifications
