include_directories(include/)

file(GLOB SAA_SRCS
        "src/*.cpp"
        "include/*.h"
        )

add_library(IndirectCallCFIPass MODULE
        # List your source files here.
        ${SAA_SRCS} src/IndirectCallCFIPass.cpp)

add_library(IndirectCallCFIPassStatic STATIC
        # List your source files here.
        ${SAA_SRCS} src/IndirectCallCFIPass.cpp)

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(IndirectCallCFIPass PRIVATE cxx_range_for cxx_auto_type)

target_compile_features(IndirectCallCFIPassStatic PRIVATE cxx_range_for cxx_auto_type)

set_target_properties(IndirectCallCFIPassStatic
        PROPERTIES POSITION_INDEPENDENT_CODE ON)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(IndirectCallCFIPass PROPERTIES
        COMPILE_FLAGS "-g -fno-rtti"
        )

set_target_properties(IndirectCallCFIPassStatic PROPERTIES
        COMPILE_FLAGS "-g -fno-rtti"
        )

# Get proper shared-library behavior (where symbols are not necessarily
# resolved when the shared library is linked) on OS X.
if(APPLE)
    set_target_properties(IndirectCallCFIPass PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            )
    set_target_properties(IndirectCallCFIPassStatic PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            )
endif(APPLE)


