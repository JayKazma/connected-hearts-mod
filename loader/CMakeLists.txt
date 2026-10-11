# Connected Hearts loader: winmm.dll placed in the game folder for a session (see Loader.cpp).
if(NOT MSVC)
    add_library(ch_loader SHARED Loader.cpp winmm_stubs.S version.rc)
    set_target_properties(ch_loader PROPERTIES OUTPUT_NAME winmm PREFIX "" ARCHIVE_OUTPUT_NAME ch_loader_import)
    target_link_options(ch_loader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/winmm.def)
endif()
