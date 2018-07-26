####
#
# Simple C library for fetching an access token
# utilizing an OAuth2 client credential workflow.
#
# Internally, this uses an embedded python interpreter
# to do all the heavy lifting.
#
###

cmake_minimum_required( VERSION 2.8 )
project( x509-scitokens-issuer )

find_package( Boost REQUIRED COMPONENTS python )
find_package( PythonLibs REQUIRED )
find_package( PythonInterp REQUIRED )

include (FindPkgConfig)
pkg_check_modules(DAVIX REQUIRED davix)
pkg_check_modules(JSON REQUIRED json-c)

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=gnu++0x")
endif()
SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")

include_directories(${PYTHON_INCLUDE_DIRS} ${BOOST_INCLUDE_DIRS} ${DAVIX_INCLUDE_DIRS} ${JSON_INCLUDE_DIRS})

add_library(X509SciTokensIssuer SHARED src/x509_token_issuer.cpp)
target_link_libraries(X509SciTokensIssuer -ldl ${Boost_PYTHON_LIBRARY} ${PYTHON_LIBRARIES} ${DAVIX_LIBRARIES} ${JSON_LIBRARIES})
set_target_properties(X509SciTokensIssuer PROPERTIES LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")

add_executable(cms-scitokens-init tools/cms-scitoken-init.cpp)
target_link_libraries(cms-scitokens-init -ldl)

add_executable(macaroon-init tools/macaroon-init.cpp)
target_link_libraries(macaroon-init -ldl)

SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

install(
  TARGETS X509SciTokensIssuer
  LIBRARY DESTINATION ${LIB_INSTALL_DIR})

install(
  TARGETS cms-scitokens-init macaroon-init
  DESTINATION bin)
