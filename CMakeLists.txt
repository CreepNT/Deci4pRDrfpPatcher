cmake_minimum_required(VERSION 3.2)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(Deci4pRDrfpPatcher)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -fno-inline -fno-builtin")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

add_executable(${PROJECT_NAME}
  main.c
)

target_link_libraries(${PROJECT_NAME}
  SceModulemgrForDriver_stub
  SceIofilemgrForDriver_stub
  SceSysclibForDriver_stub
  SceDebugForDriver_stub
  SceCpuForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
)

if (BUILD_363)
  target_link_libraries(${PROJECT_NAME}
    SceModulemgrForKernel_363_stub
  )
  message("Building for 3.63+ System Software")
  set(ARTIFACT_SUFFIX "_363")
else()
  target_link_libraries(${PROJECT_NAME}
    SceModulemgrForKernel_stub
  )
  message("Building for pre-3.63 System Software")
endif()

set_target_properties(${PROJECT_NAME}
  PROPERTIES LINK_FLAGS "-nostdlib"
)

vita_create_self(${PROJECT_NAME}${ARTIFACT_SUFFIX}.skprx ${PROJECT_NAME}
  CONFIG module.yml
  UNSAFE
)