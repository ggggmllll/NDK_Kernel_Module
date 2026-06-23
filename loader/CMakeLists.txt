# 使用者模块构建：
#   目录内 *.c  +  kmod 基础设施库（含 cfi_entry_stubs.S）
#   → ld -r -T <root>/module.lds  →  <MODULE_NAME>_merged.o
#   → KPatcher  →  <MODULE_NAME>.ko

# 收集本目录所有 .c 作为模块源码（使用者把自己的 .c 放进本目录即可）
file(GLOB MODULE_C_SRC CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

add_library(module_objs OBJECT ${MODULE_C_SRC})
target_link_libraries(module_objs PRIVATE kmod)
# 内核模块 code model（见根 CMakeLists 的 KMOD_FLAGS 说明）：
# 必须 -fno-PIC，否则外部符号走 GOT，真机内核模块加载器拒绝 reloc 311/312。
target_compile_options(module_objs PRIVATE ${KMOD_FLAGS})

set(MERGED_OBJ "${CMAKE_BINARY_DIR}/${MODULE_NAME}_merged.o")
set(OBJS_RSP   "${CMAKE_BINARY_DIR}/${MODULE_NAME}_objs.rsp")

# 响应文件：列出 kmod + 模块的所有 .o。用 $<JOIN:..., > 把分号换成空格，
# 绕开 Windows cmd 下 "$<TARGET_OBJECTS>" 的分号被当成单个参数的问题。
file(GENERATE OUTPUT "${OBJS_RSP}"
     CONTENT "$<JOIN:$<TARGET_OBJECTS:kmod>, > $<JOIN:$<TARGET_OBJECTS:module_objs>, >")

# ---- merged.o：ld -r -T module.lds 合并 ----
add_custom_command(OUTPUT "${MERGED_OBJ}"
    COMMAND "${CMAKE_LINKER}" -r -T "${CMAKE_SOURCE_DIR}/module.lds"
            -o "${MERGED_OBJ}" "@${OBJS_RSP}"
    DEPENDS kmod module_objs "${CMAKE_SOURCE_DIR}/module.lds"
    COMMENT "LD -r -T module.lds → ${MODULE_NAME}_merged.o")

# ---- .ko：KPatcher ----
set(KO_FILE "${CMAKE_BINARY_DIR}/${MODULE_NAME}.ko")
add_custom_command(OUTPUT "${KO_FILE}"
    COMMAND "${KPATCHER}" "${MERGED_OBJ}"
            -o "${KO_FILE}"
            -n "${MODULE_NAME}" -l GPL
            -N VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver
    DEPENDS "${MERGED_OBJ}"
    COMMENT "KPatcher → ${MODULE_NAME}.ko")

add_custom_target(ko ALL DEPENDS "${KO_FILE}")
