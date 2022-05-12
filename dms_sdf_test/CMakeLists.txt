set(CMAKE_C_COMPILER "gcc")

# 添加所有源文件
aux_source_directory(src SRC_FILES)
aux_source_directory(src/alg ALG_FILES)
set(SRC_FILES ${SRC_FILES} ${ALG_FILES})

add_definitions("-std=c99 -fPIC  -O2")

# 生成可执行文件
add_executable(test ${SRC_FILES})

target_link_libraries(test pcisdf)
target_link_libraries(test pthread)
