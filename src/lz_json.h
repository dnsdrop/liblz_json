#pragma once

enum lz_json_vtype_e {
    lz_json_vtype_string = 0,
    lz_json_vtype_number,
    lz_json_vtype_object,
    lz_json_vtype_array,
    lz_json_vtype_bool,
    lz_json_vtype_null
};

struct lz_json_s;

typedef enum lz_json_vtype_e lz_json_vtype;
typedef struct lz_json_s     lz_json;

typedef int (* lz_json_key_filtercb)(const char * key, lz_json * val);


/**
 * @brief creates a new unordered-keyval context
 *
 * @return lz_json context with a vtype of 'lz_json_vtype_object'
 */
LZ_EXPORT lz_json * lz_json_object_new(void);


/**
 * @brief creates a new ordered array of lz_json context values
 *
 * @return lz_json context with a vtype of 'lz_json_vtype_array'
 */
LZ_EXPORT lz_json * lz_json_array_new(void);


/**
 * @brief frees data associated with a lz_json context. Objects and arrays
 *        will free all the resources contained within in a recursive manner.
 *
 * @param js
 */
LZ_EXPORT void lz_json_free(lz_json * js);

/**
 * @brief creates a lz_json context for a null terminated string
 *        and copies the original string
 *
 * @param str
 *
 * @return lz_json context with vtype of 'lz_json_vtype_string'
 */
LZ_EXPORT lz_json * lz_json_string_new(const char * str);


/**
 * @brief a variant of lz_json_string_new which can be faster if you
 *          already know the length.
 *
 * @param str
 * @param len length of the string
 *
 * @return
 */
LZ_EXPORT lz_json * lz_json_string_new_len(const char * str, size_t len);


/**
 * @brief creates a lz_json context for a number. Note: this only supports
 *        unsigned int right now (casted for signed).
 *
 * @param num
 *
 * @return lz_json context with vtype of 'lz_json_vtype_number'
 */
LZ_EXPORT lz_json * lz_json_number_new(unsigned int num);


/**
 * @brief creates a lz_json context for a boolean value.
 *
 * @param boolean either true or false
 *
 * @return lz_json context with vtype of 'lz_json_vtype_bool'
 */
LZ_EXPORT lz_json * lz_json_boolean_new(bool boolean);


/**
 * @brief creates a lz_json context for a null value
 *
 * @return lz_json context with vtype of 'lz_json_vtype_null'
 */
LZ_EXPORT lz_json * lz_json_null_new(void);

/**
 * @brief parse a buffer containing raw json and convert it to the
 *        internal lz_json.
 *
 * @param data the buffer to parse
 * @param len the length of the data in the buffer
 * @param n_read the number of bytes which were parsed will be stored
 *        here.
 *
 * @return lz_json context if valid json, NULL on error (also see n_read above)
 */
LZ_EXPORT lz_json * lz_json_parse_buf(const char * data, size_t len, size_t * n_read);

/**
 * @brief wrapper around lz_json_parse_buf but opens, reads, parses, and closes
 *        a file with JSON data.
 *
 * @param filename
 * @param n_read number of bytes parsed
 *
 * @return see lz_json_parse_buf
 */
LZ_EXPORT lz_json * lz_json_parse_file(const char * filename, size_t * n_read);

/* these next set of parser functions are self explainatory, and will probably be
 * made private in the future.
 */
LZ_EXPORT lz_json * lz_json_parse_object(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_array(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_value(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_string(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_number(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_key(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_null(const char * data, size_t len, size_t * n_read);
LZ_EXPORT lz_json * lz_json_parse_boolean(const char * data, size_t len, size_t * n_read);

/**
 * @brief returns the underlying type of the lz_json context
 *
 * @param js
 *
 * @return
 */
LZ_EXPORT lz_json_vtype lz_json_get_type(lz_json * js);


/**
 * @brief returns the underlying lz_kvmap ADT for an object
 *
 * @param js
 *
 * @return lz_kvmap on success, NULL if the underlying data
 *         is not an object.
 */
LZ_EXPORT lz_kvmap * lz_json_get_object(lz_json * js);

/**
 * @brief returns the underlying lz_tailq ADT for an array
 *
 * @param js
 *
 * @return lz_tailq on success, NULL if the underlying data is
 *         not an array.
 */
LZ_EXPORT lz_tailq * lz_json_get_array(lz_json * js);


/**
 * @brief fetches the lz_json value in an array at a specific index
 *
 * @param js
 * @param index
 *
 * @return the lz_json value, NULL if not found
 */
LZ_EXPORT lz_json * lz_json_get_array_index(lz_json * js, int index);


/**
 * @brief return the underlying number
 *
 * @param js
 *
 * @return
 */
LZ_EXPORT unsigned int lz_json_get_number(lz_json * js);


/**
 * @brief fetches the underlying string of the lz_json context
 *
 * @param js
 *
 * @return the string on success, NULL if underlying data is not a string
 */
LZ_EXPORT const char * lz_json_get_string(lz_json * js);


/**
 * @brief boolean fetch
 *
 * @param js
 *
 * @return true or false
 */
LZ_EXPORT bool lz_json_get_boolean(lz_json * js);


/**
 * @brief null fetch
 *
 * @param js
 *
 * @return 1 if null, -1 if underlying data is not a null
 */
LZ_EXPORT int lz_json_get_null(lz_json * js);


/**
 * @brief size fetch of underlying lz_json data:
 *          lz_json_vtype_string : length of the string
 *          lz_json_vtype_array  : the number of entries in the array
 *          lz_json_vtype_object : number of entries in the object
 *
 * @param js
 *
 * @return 0 if the underlying type doesn't have a size, otherwise see above
 */
LZ_EXPORT ssize_t lz_json_get_size(lz_json * js);


/**
 * @brieffetch lz_json data using a special syntax
 *
 *        if the json is { "a" : 1, "b" : [1, 2, 3, { "foo": "bar" }], "c" : {"hi" : null} }
 *
 *        and you would like to get the second element of the key "b" the syntax would be:
 *           "b.[2]"
 *
 *        or to get the value of "foo" in this example:
 *           "b.[4].foo"
 *
 * @param js
 * @param path
 *
 * @return
 */
LZ_EXPORT lz_json * lz_json_get_path(lz_json * js, const char * path);


/**
 * @brief add a string : lz_json context to an existing lz_json object
 *
 * @param obj
 * @param key
 * @param val
 *
 * @return
 */
LZ_EXPORT int lz_json_object_add(lz_json * obj, const char * key, lz_json * val);


/**
 * @brief same as lz_json_object_add, except if the length of the key is known,
 *        you can reduce overhead
 *
 * @param o
 * @param k
 * @param kl
 * @param v
 *
 * @return
 */
LZ_EXPORT int lz_json_object_add_klen(lz_json * o, const char * k, size_t kl, lz_json * v);


/**
 * @brief add a lz_json context to a lz_json array context
 *
 * @param array
 * @param val
 *
 * @return
 */
LZ_EXPORT int lz_json_array_add(lz_json * array, lz_json * val);


/**
 * @brief can be used on either lz_json arrays or objects. For arrays, just omit the key
 *
 * @param obj
 * @param k
 * @param val
 *
 * @return
 */
LZ_EXPORT int lz_json_add(lz_json * obj, const char * k, lz_json * val);


/**
 * @brief converts the lz_json ctx to a valid JSON string
 *
 * @param json
 * @param buf user supplied buffer
 * @param buf_len the length of the buffer
 *
 * @return number of bytes copied into the buffer
 */
LZ_EXPORT ssize_t lz_json_to_buffer(lz_json * json, char * buf, size_t buf_len);


#if 0
/**
 * @brief same as lz_json_to_buffer but does not escape strings
 *
 * @param json
 * @param buf
 * @param buf_len
 *
 * @return
 */
LZ_EXPORT ssize_t lz_json_to_buffer_nescp(lz_json * json, char * buf, size_t buf_len);
#endif


/**
 * @brief converts to a malloc'd JSON string
 *
 * @param json
 * @param len
 *
 * @return
 */
LZ_EXPORT char * lz_json_to_buffer_alloc(lz_json * json, size_t * len);


/**
 * @brief prints string version of json context
 *
 * @param [OUT] output file pointer
 * @param [IN]  json encoded structure
 *
 */
LZ_EXPORT void lz_json_print(FILE * out, lz_json * json);

/**
 * @brief compares two lz_json contexts to determine if they match, if the filtercb
 *        argument is not NULL, and the type being compared currently is an array or object,
 *        each ts_json context is passed to the callback. If the callback returns -1, that
 *        value will not be compared to the other.
 *
 * @param j1
 * @param j2
 * @param cb
 *
 * @return
 */
LZ_EXPORT int lz_json_compare(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb);
LZ_EXPORT int lz_json_init(void) __attribute__((constructor(101)));

#define lz_json_fprintf(FP, JSON) do {                         \
        char    _out[2048] = { 0 };                            \
        ssize_t _outlen;                                       \
                                                               \
        _outlen = lz_json_to_buffer(JSON, _out, sizeof(_out)); \
        fprintf(FP, "%.*s\n", (int)_outlen, _out);             \
} while (0)

