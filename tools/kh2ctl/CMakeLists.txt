add_executable(kh2ctl
    src/main.cpp
    src/world_resync.cpp
    src/testkit_cmds.cpp
)

set_target_properties(kh2ctl PROPERTIES OUTPUT_NAME "chctl")

target_link_libraries(kh2ctl PRIVATE
    kh2coop_runtime
    user32
    ole32
    dbghelp
)

option(KH2COOP_PORTABLE_PACKAGE "Require package-root cwd and keep canonical rig state there" OFF)
if(KH2COOP_PORTABLE_PACKAGE)
    target_compile_definitions(kh2ctl PRIVATE KH2COOP_PORTABLE_PACKAGE=1)
else()
    target_compile_definitions(kh2ctl PRIVATE KH2COOP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
endif()

# chtest: the developer Test tab's helper. Every command, rig state under <install>\build\rig.
# Never part of the release package.
add_executable(chtest
    src/main.cpp
    src/world_resync.cpp
    src/testkit_cmds.cpp
)
target_link_libraries(chtest PRIVATE kh2coop_runtime user32 ole32 dbghelp)
target_compile_definitions(chtest PRIVATE KH2COOP_TEST_KIT_TOOL=1)
