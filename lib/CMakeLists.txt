include (ExternalProject)

if (NOT LIBLZ_CORE)
	ExternalProject_Add (liblz_core
		GIT_REPOSITORY git@gitlab.com:unicornshaverainbows/liblz_core.git
		GIT_TAG        master
		UPDATE_COMMAND ""
		CMAKE_ARGS
			-DCMAKE_INSTALL_PREFIX:PATH=${PROJECT_BINARY_DIR}
			-DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE})
endif ()
