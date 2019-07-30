add_library           (lz_json ${LIBLZ_OBJ_TYPE} lz_json.c)
target_link_libraries (lz_json lz_core)

install               (TARGETS lz_json DESTINATION lib)
install               (FILES lz_json.h DESTINATION include/liblz)

#if (LIBLUA)
#	add_library           (lz_jsonL ${LIBLZ_OBJ_TYPE} lz_jsonL.c)
#	target_link_libraries (lz_jsonL lz_json ${LIBLUA})
#
#	install               (TARGETS lz_jsonL DESTINATION lib)
#	install               (FILES lz_jsonL.h DESTINATION include/liblz)
#endif()

