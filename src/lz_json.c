#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>

#include <liblz.h>
#include <liblz/lzapi.h>

#include "lz_json.h"

enum lz_j_state {
    lz_j_s_start = 0,
    lz_j_s_end
};

enum lz_j_arr_state {
    lz_j_arr_s_val = 0,
    lz_j_arr_s_comma,
    lz_j_arr_s_end
};

enum lz_j_obj_state {
    lz_j_obj_s_key = 0,
    lz_j_obj_s_delim,
    lz_j_obj_s_val,
    lz_j_obj_s_comma,
    lz_j_obj_s_end
};

typedef enum lz_j_state     lz_j_state;
typedef enum lz_j_arr_state lz_j_arr_state;
typedef enum lz_j_obj_state lz_j_obj_state;

static __thread void * __js_heap = NULL;

struct __jbuf {
    char  * buf;
    size_t  buf_idx;
    size_t  buf_len;
    ssize_t written;
    int     dynamic;
    bool    escape;
};


struct lz_json_s {
    lz_json_vtype type;
    union {
        lz_kvmap   * object;
        lz_tailq   * array;
        char       * string;
        unsigned int number;
        bool         boolean;
    };

    size_t slen;
    void   (* freefn)(void *);
};

static lz_json * js_parse_value_(const char *, size_t, size_t *);
static int       js_compare_(lz_json *, lz_json *, lz_json_key_filtercb);

static int       js_json_to_buffer_(lz_json * json, struct __jbuf * jbuf);
static int       js_addbuf_(struct __jbuf * jbuf, const char * buf, size_t len);

#define JS_STATIC_GET_FNDEF(return_type, return_err, arg_cmp, arg_name) \
    static return_type                                                  \
    js_get_ ## arg_name ## _(lz_json * js) {                            \
        if (lz_unlikely(js == NULL)) {                                  \
            return return_err;                                          \
        }                                                               \
                                                                        \
        return (js->type == arg_cmp) ? js->arg_name : return_err;       \
    }                                                                   \
    lz_alias(js_get_ ## arg_name ## _, lz_json_get_ ## arg_name)


JS_STATIC_GET_FNDEF(lz_kvmap *, NULL, lz_json_vtype_object, object);
JS_STATIC_GET_FNDEF(lz_tailq *, NULL, lz_json_vtype_array, array);
JS_STATIC_GET_FNDEF(unsigned int, 0, lz_json_vtype_number, number);
JS_STATIC_GET_FNDEF(const char *, NULL, lz_json_vtype_string, string);
JS_STATIC_GET_FNDEF(bool, false, lz_json_vtype_bool, boolean);

static int
js_get_null_(lz_json * js)
{
    if (lz_unlikely(js == NULL)) {
        return -1;
    }

    if (js->type != lz_json_vtype_null) {
        return -1;
    } else {
        return 1;
    }
}

static lz_json_vtype
js_get_type_(lz_json * js)
{
    if (lz_unlikely(js == NULL)) {
        return -1;
    }

    return js->type;
}

static ssize_t
js_get_size_(lz_json * js)
{
    if (lz_unlikely(js == NULL)) {
        return -1;
    }

    switch (js->type) {
        case lz_json_vtype_string:
            return (ssize_t)js->slen;
        case lz_json_vtype_array:
            return lz_tailq_size(js->array);
        case lz_json_vtype_object:
            return lz_kvmap_get_size(js->object);
        case lz_json_vtype_bool:
            return js->boolean == true ? 1 : 0;
        default:
            return 0;
    }

    return 0;
}

static lz_json *
js_new_(lz_json_vtype type)
{
    lz_json * lz_j;

    /* if lz_json_init() was never called, this leads to bad things! */
    if (!(lz_j = lz_heap_alloc(__js_heap))) {
        return NULL;
    }

    lz_j->type   = type;
    lz_j->freefn = NULL;

    return lz_j;
}

static void
js_free_(lz_json * js)
{
    if (js == NULL) {
        return;
    }

    switch (js->type) {
        case lz_json_vtype_string:
            lz_safe_free(js->string, free);
            break;
        case lz_json_vtype_object:
            lz_safe_free(js->object, lz_kvmap_free);
            break;
        case lz_json_vtype_array:
            lz_safe_free(js->array, lz_tailq_free);
            break;
        default:
            break;
    }

    lz_heap_free(__js_heap, js);
}

static lz_json *
js_object_new_(void)
{
    lz_json * js;

    if (!(js = js_new_(lz_json_vtype_object))) {
        return NULL;
    }

    if (!(js->object = lz_kvmap_new(10))) {
        lz_safe_free(js, js_free_);

        return NULL;
    }

    js->freefn = (void (*))lz_kvmap_free;

    return js;
}

static lz_json *
js_array_new_(void)
{
    lz_json * js;

    if (!(js = js_new_(lz_json_vtype_array))) {
        return NULL;
    }

    if (!(js->array = lz_tailq_new())) {
        lz_safe_free(js, js_free_);

        return NULL;
    }

    js->freefn = (void (*))lz_tailq_free;

    return js;
}

static lz_json *
js_string_new_len_(const char * str, size_t slen)
{
    lz_json * js;

    if (str == NULL || slen <= 0) {
        return NULL;
    }

    if (!(js = js_new_(lz_json_vtype_string))) {
        return NULL;
    }

    if (!(js->string = malloc(slen + 1))) {
        js_free_(js);

        return NULL;
    }

    js->string[slen] = '\0';

    if (memcpy(js->string, str, slen) != js->string) {
        js_free_(js);

        return NULL;
    }

    js->slen   = slen;
    js->freefn = free;

    return js;
}

static lz_json *
js_string_new_(const char * str)
{
    return js_string_new_len_(str, strlen(str));
}

static lz_json *
js_number_new_(unsigned int num)
{
    lz_json * js;

    if (!(js = js_new_(lz_json_vtype_number))) {
        return NULL;
    }

    js->number = num;

    return js;
}

static lz_json *
js_boolean_new_(bool boolean)
{
    lz_json * js;

    if (!(js = js_new_(lz_json_vtype_bool))) {
        return NULL;
    }

    js->boolean = boolean;

    return js;
}

static lz_json *
js_null_new_(void)
{
    return js_new_(lz_json_vtype_null);
}

static int
js_object_add_(lz_json * dst, const char * key, lz_json * val)
{
    if (lz_unlikely(!dst || !key || !val)) {
        return -1;
    }

    if (dst->type != lz_json_vtype_object) {
        return -1;
    }

    if (!lz_kvmap_add(dst->object, key, val, (void (*))lz_json_free)) {
        return -1;
    }

    return 0;
}

static int
js_object_add_klen_(lz_json * dst, const char * key, size_t klen, lz_json * val)
{
    if (lz_unlikely(dst == NULL)) {
        return -1;
    }

    if (dst->type != lz_json_vtype_object) {
        return -1;
    }

    if (!lz_kvmap_add_wklen(dst->object,
                            key, klen, val,
                            (void (*))lz_json_free)) {
        return -1;
    }

    return 0;
}

static int
js_array_add_(lz_json * dst, lz_json * src)
{
    if (lz_unlikely(dst == NULL)) {
        return -1;
    }

    if (dst->type != lz_json_vtype_array) {
        return -1;
    }

    if (!lz_tailq_append(dst->array, src, 1, (void (*))lz_json_free)) {
        return -1;
    }

    return 0;
}

static lz_json *
js_parse_string_(const char * data, size_t len, size_t * n_read)
{
    unsigned char ch;
    size_t        i;
    size_t        buflen;
    char          buf[len + 128];
    int           buf_idx;
    int           escaped;
    bool          error;
    lz_json     * js;

    if (!data || !len || *data != '"') {
        /* *n_read = 0; */
        return NULL;
    }

    escaped = 0;
    buf_idx = 0;
    error   = false;
    js      = NULL;
    buflen  = len + 128;

    len--;
    data++;

    for (i = 0; i < len; i++)
    {
        if (buf_idx >= buflen) {
            error = true;
            errno = ENOBUFS;
            goto end;
        }

        ch = data[i];

        if (!lz_isascii(ch)) {
            error = true;
            goto end;
        }

        if (escaped) {
            switch (ch) {
                case '"':
                case '/':
                case 'b':
                case 'f':
                case 'n':
                case 'r':
                case 't':
                case '\\':
                    escaped        = 0;
                    buf[buf_idx++] = ch;
                    break;
                default:
                    error          = true;
                    goto end;
            }
            continue;
        }

        if (ch == '\\') {
            escaped = 1;
            continue;
        }

        if (ch == '"') {
            js = js_string_new_len_(buf, buf_idx);
            i += 1;
            break;
        }

        buf[buf_idx++] = ch;
    }

end:
    *n_read += i;

    if (error == true) {
        lz_safe_free(js, js_free_);

        return NULL;
    }

    return js;
} /* js_parse_string_ */

static lz_alias(js_parse_string_, js_parse_key_);

static lz_json *
js_parse_number_(const char * data, size_t len, size_t * n_read)
{
    unsigned char ch;
    char          buf[len];
    int           buf_idx;
    size_t        i;
    lz_json     * js;

    if (!data || !len) {
        return NULL;
    }

    js      = NULL;
    buf_idx = 0;

    if (memset(buf, 0, sizeof(buf)) != buf) {
        return NULL;
    }

    for (i = 0; i < len; i++)
    {
        ch = data[i];

        if (!isdigit(ch) || (len == 1 && isdigit(ch))) {
            js = js_number_new_((unsigned int)lz_atoi(buf, buf_idx));
            break;
        }

        buf[buf_idx++] = ch;
    }

    *n_read += (len == 1) ? 1 : i - 1;

    return js;
}

#define J_TRUE_CMP   0x657572
#define J_FALSE_CMP  0x65736c61
#define J_TRUE_MASK  0xFFFFFF
#define J_FALSE_MASK 0xFFFFFFFF

static lz_json *
js_parse_boolean_(const char * data, size_t len, size_t * n_read)
{
    lz_json * js;

    if (lz_unlikely(len < 4)) {
        /* need at LEAST 'true' */
        *n_read = 0;
        return NULL;
    }

    js = NULL;

    /* here we cast our data string to an integer, mask it by the
     * number of words we want to see, then match the integer version
     * of the string.
     */
    switch (*data) {
        case 't':
            if ((*((uint32_t *)(data + 1)) & J_TRUE_MASK) == J_TRUE_CMP) {
                *n_read += 3;

                if (!(js = js_boolean_new_(true))) {
                    return NULL;
                }
            }

            break;
        case 'f':
            if (len < 5) {
                return NULL;
            }

            if ((*((uint32_t *)(data + 1)) & J_FALSE_MASK) == J_FALSE_CMP) {
                *n_read += 4;

                if (!(js = js_boolean_new_(false))) {
                    return NULL;
                }
            }

            break;
        default:
            return NULL;
    } /* switch */

    return js;
}     /* js_parse_boolean_ */

static lz_json *
js_parse_null_(const char * data, size_t len, size_t * n_read)
{
    if (data == NULL || len < 4) {
        return NULL;
    }

    if (!lz_str30_cmp(data, 'n', 'u', 'l', 'l')) {
        return NULL;
    }

    *n_read += 4;

    return js_null_new_();
}

static lz_json *
js_parse_array_(const char * data, size_t len, size_t * n_read)
{
    unsigned char  ch;
    unsigned char  end_ch;
    size_t         i;
    bool           error;
    size_t         b_read;
    lz_j_arr_state state;
    lz_json      * js;


    if (!data || !len || *data != '[') {
        /* *n_read = 0; */
        return NULL;
    }

    data++;
    len--;

    js     = js_array_new_();
    state  = lz_j_arr_s_val;
    error  = false;
    b_read = 0;
    end_ch = 0;

    for (i = 0; i < len; i++)
    {
        lz_json * val;

        ch = data[i];

        if (isspace(ch)) {
            continue;
        }

        switch (state) {
            case lz_j_arr_s_val:
                if (ch == ']') {
                    end_ch = ch;
                    state  = lz_j_arr_s_end;
                    break;
                }

                if (!(val = js_parse_value_(&data[i], (len - i), &b_read))) {
                    error = true;
                    goto end;
                }

                i     += b_read;
                b_read = 0;

                js_array_add_(js, val);

                state = lz_j_arr_s_comma;

                if ((i + 1) == len) {
                    end_ch = data[i];
                }

                break;
            case lz_j_arr_s_comma:
                switch (ch) {
                    case ',':
                        state  = lz_j_arr_s_val;
                        break;
                    case ']':
                        end_ch = ch;
                        state  = lz_j_arr_s_end;
                        break;
                    default:
                        error  = true;
                        goto end;
                }
                break;
            case lz_j_arr_s_end:
                goto end;
        } /* switch */
    }
end:
    *n_read += i;

    if ((end_ch != ']' || error == true)) {
        lz_safe_free(js, js_free_);
        return NULL;
    }

    return js;
} /* js_parse_array_ */

static lz_json *
js_parse_object_(const char * data, size_t len, size_t * n_read)
{
    unsigned char  ch;
    unsigned char  end_ch;
    size_t         i;
    lz_json      * js;
    lz_json      * key;
    lz_json      * val;
    lz_j_obj_state state;
    bool           error;
    size_t         b_read;

    if (*data != '{') {
        /* *n_read = 0; */
        return NULL;
    }

    if (!(js = js_object_new_())) {
        return NULL;
    }

    state  = lz_j_obj_s_key;
    key    = NULL;
    val    = NULL;
    error  = false;
    b_read = 0;
    end_ch = 0;

    data++;
    len--;

    for (i = 0; i < len; i++)
    {
        ch = data[i];

        if (isspace(ch)) {
            continue;
        }

        switch (state) {
            case lz_j_obj_s_key:
                if (ch == '}') {
                    end_ch = ch;
                    state  = lz_j_obj_s_end;
                    break;
                }

                if (!(key = js_parse_key_(&data[i], (len - i), &b_read))) {
                    error = true;
                    i    += b_read;
                    goto end;
                }

                i     += b_read;
                b_read = 0;
                state  = lz_j_obj_s_delim;
                break;
            case lz_j_obj_s_delim:
                if (ch != ':') {
                    error = true;
                    goto end;
                }

                state = lz_j_obj_s_val;
                break;

            case lz_j_obj_s_val:
                if (!(val = js_parse_value_(&data[i], (len - i), &b_read))) {
                    error = true;
                    i    += b_read;
                    goto end;
                }

                i     += b_read;
                b_read = 0;

                if (js_object_add_(js, key->string, val) == -1) {
                    error = true;
                    goto end;
                }

                lz_safe_free(key, js_free_);

                key   = NULL;
                state = lz_j_obj_s_comma;

                break;

            case lz_j_obj_s_comma:
                switch (ch) {
                    case ',':
                        state  = lz_j_obj_s_key;
                        break;
                    case '}':
                        end_ch = ch;
                        state  = lz_j_obj_s_end;
                        break;
                    default:
                        error  = true;
                        goto end;
                }
                break;
            case lz_j_obj_s_end:
                goto end;
        } /* switch */
    }

end:
    *n_read += i;

    lz_safe_free(key, js_free_);

    if ((end_ch != '}' || error == true)) {
        lz_safe_free(js, js_free_);
        return NULL;
    }

    return js;
} /* js_parse_object_ */

static lz_json *
js_parse_buf_(const char * data, size_t len, size_t * n_read)
{
    unsigned char ch;
    size_t        b_read;
    size_t        i;
    lz_json     * js;
    lz_j_state    state;

    js     = NULL;
    b_read = 0;
    state  = lz_j_s_start;

    for (i = 0; i < len; i++)
    {
        ch = data[i];

        if (isspace(ch)) {
            continue;
        }

        switch (state) {
            case lz_j_s_start:
                switch (ch) {
                    case '{':
                        if (!(js = js_parse_object_(&data[i], (len - i), &b_read))) {
                            *n_read += b_read;
                            return NULL;
                        }

                        i     += b_read;
                        b_read = 0;
                        break;
                    case '[':
                        if (!(js = js_parse_array_(&data[i], (len - i), &b_read))) {
                            *n_read += b_read;
                            return NULL;
                        }

                        i       += b_read;
                        b_read   = 0;
                        break;
                    default:
                        *n_read += i;
                        return NULL;
                } /* switch */

                state = lz_j_s_end;
                break;
            case lz_j_s_end:
                break;
        }         /* switch */
    }

    *n_read += i;

    return js;
} /* js_parse_buf_ */

static lz_json *
js_parse_file_(const char * filename, size_t * bytes_read)
{
    lz_json * json   = NULL;
    FILE    * fp     = NULL;
    char    * buf    = NULL;
    size_t    n_read = 0;
    long      file_size;

    if (filename == NULL) {
        return NULL;
    }

    do {
        if (!(fp = fopen(filename, "re"))) {
            break;
        }

        if (fseek(fp, 0L, SEEK_END) == -1) {
            break;
        }

        if ((file_size = ftell(fp)) == -1) {
            break;
        }

        if (fseek(fp, 0L, SEEK_SET) == -1) {
            break;
        }

        /* allocate 1 more than the size, just incase there is not an EOL
         * terminator in the file.
         */
        if (!(buf = calloc(file_size + 1, 1))) {
            break;
        }

        if (fread(buf, 1, file_size, fp) != file_size) {
            break;
        }

        if (buf[file_size] == 0) {
            /* just make sure we have SOME type of EOL terminator by placing a
             * \n in it. */
            buf[file_size] = '\n';
            file_size     += 1;
        }

        if (!(json = js_parse_buf_(buf, file_size, &n_read))) {
            break;
        }
    } while (0);

    if (fp != NULL) {
        fclose(fp);
    }

    *bytes_read = n_read;

    lz_safe_free(buf, free);
    return json;
} /* lz_json_parse_file */

static lz_json *
js_get_array_index_(lz_json * array, int offset)
{
    lz_tailq * list;

    if (!(list = js_get_array_(array))) {
        return NULL;
    }

    return (lz_json *)lz_tailq_get_at_index(list, offset);
}

enum path_state {
    path_state_reading_key,
    path_state_reading_array,
    path_state_reading_array_end
};


static lz_json *
js_get_path_(lz_json * js, const char * path)
{
    char            buf[strlen(path) + 1];
    int             buf_idx;
    lz_kvmap      * object;
    lz_json       * prev;
    unsigned char   ch;
    size_t          i;
    enum path_state state;

    if (lz_unlikely(js == NULL || path == NULL)) {
        return NULL;
    }

    prev    = js;
    object  = NULL;
    buf_idx = 0;
    buf[0]  = '\0';
    state   = path_state_reading_key;

    for (i = 0; i < strlen(path) + 1; i++)
    {
        ch = path[i];

        switch (state) {
            case path_state_reading_key:
                switch (ch) {
                    case '[':
                        state = path_state_reading_array;
                        break;
                    case '\0':
                    case '.':
                        /* XXX: if there is a failed allocation, this might
                         *      leak memory from `object`
                         */
                        if (!(object = js_get_object_(prev))) {
                            return NULL;
                        }

                        if (!(prev = lz_kvmap_find(object, buf))) {
                            return NULL;
                        }

                        buf[0]         = '\0';
                        buf_idx        = 0;
                        break;
                    default:
                        buf[buf_idx++] = ch;
                        buf[buf_idx]   = '\0';
                        break;
                } /* switch */
                break;
            case path_state_reading_array:
                switch (ch) {
                    case ']':
                        prev = js_get_array_index_(prev,
                                                   lz_atoi(buf, buf_idx));

                        if (prev == NULL) {
                            return NULL;
                        }


                        buf[0]  = '\0';
                        buf_idx = 0;
                        state   = path_state_reading_array_end;

                        break;
                    default:
                        buf[buf_idx++] = ch;
                        buf[buf_idx]   = '\0';
                        break;
                } /* switch */
                break;
            case path_state_reading_array_end:
                state = path_state_reading_key;
                break;
        }         /* switch */

        if (ch == '\0') {
            break;
        }
    }

    return (prev != js) ? prev : NULL;
} /* js_get_path_ */

static int
js_add_(lz_json * obj, const char * key, lz_json * val)
{
    if (obj == NULL) {
        return -1;
    }

    if (key == NULL) {
        if (obj->type != lz_json_vtype_array) {
            return -1;
        }

        return js_array_add_(obj, val);
    }

    return js_object_add_(obj, key, val);
}

static int
js_addbuf_vprintf_(struct __jbuf * jbuf, const char * fmt, va_list ap)
{
    char tmpbuf[jbuf->buf_len - jbuf->buf_idx];
    int  sres;

    if (lz_unlikely(jbuf == NULL)) {
        return -1;
    }

    sres = vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);

    if (sres >= sizeof(tmpbuf) || sres < 0) {
        return -1;
    }

    return js_addbuf_(jbuf, tmpbuf, (size_t)sres);
}

static int
js_addbuf_printf_(struct __jbuf * jbuf, const char * fmt, ...)
{
    va_list ap;
    int     sres;

    if (lz_unlikely(jbuf == NULL)) {
        return -1;
    }

    va_start(ap, fmt);
    {
        sres = js_addbuf_vprintf_(jbuf, fmt, ap);
    }
    va_end(ap);

    return sres;
}

static int
js_addbuf_(struct __jbuf * jbuf, const char * buf, size_t len)
{
    if (lz_unlikely(jbuf == NULL)) {
        return -1;
    }

    if (len == 0 || buf == NULL) {
        return 0;
    }

    if ((jbuf->buf_idx + len) > jbuf->buf_len) {
        /* should we allocate this buffer ourselves? If so, let it roll! */
        if (jbuf->dynamic == 1) {
            /* give daddy a little more memory, just one memory */
            jbuf->buf = realloc(jbuf->buf, (size_t)(jbuf->buf_len + len + 32));

            if (lz_unlikely(jbuf->buf == NULL)) {
                return -1;
            }

            jbuf->buf_len += len + 32;
        } else {
            return -1;
        }
    }

    memcpy(&jbuf->buf[jbuf->buf_idx], buf, len);

    jbuf->buf_idx += len;
    jbuf->written += len;

    return 0;
}

static const char digits[] =
    "0001020304050607080910111213141516171819"
    "2021222324252627282930313233343536373839"
    "4041424344454647484950515253545556575859"
    "6061626364656667686970717273747576777879"
    "8081828384858687888990919293949596979899";

static int
js_addbuf_number_(struct __jbuf * jbuf, unsigned int num)
{
    char     buf[32]; /* 18446744073709551615 64b, 20 characters */
    char   * buffer          = (char *)buf;
    char   * buffer_end      = buffer + 32;
    char   * buffer_end_save = buffer + 32;
    unsigned index;

    if (lz_unlikely(jbuf == NULL)) {
        return -1;
    }

    *--buffer_end = '\0';

    while (num >= 100)
    {
        index         = (num % 100) * 2;
        num          /= 100;

        *--buffer_end = digits[index + 1];
        *--buffer_end = digits[index];
    }

    if (num < 10) {
        *--buffer_end = (char)('0' + num);
    } else {
        index         = (unsigned)(num * 2);

        *--buffer_end = digits[index + 1];
        *--buffer_end = digits[index];
    }

    return js_addbuf_(jbuf, buffer_end,
                      (size_t)(buffer_end_save - buffer_end - 1));
}

static int
js_number_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    if (json->type != lz_json_vtype_number) {
        return -1;
    }

    return js_addbuf_number_(jbuf, json->number);
}

static int
js_escape_string_(const char * str, size_t len, struct __jbuf * jbuf)
{
    unsigned char ch;
    size_t        i;

    if (lz_unlikely(str == NULL || jbuf == NULL)) {
        return -1;
    }

    for (i = 0; i < len; i++)
    {
        ch = str[i];

        switch (ch) {
            default:
                if (js_addbuf_(jbuf, (const char *)&ch, 1) == -1) {
                    return -1;
                }

                break;
            case '\n':
                if (js_addbuf_(jbuf, "\\n", 2) == -1) {
                    return -1;
                }

                break;
            case '"':
                if (js_addbuf_(jbuf, "\\\"", 2) == -1) {
                    return -1;
                }

                break;
            case '\t':
                if (js_addbuf_(jbuf, "\\t", 2) == -1) {
                    return -1;
                }

                break;
            case '\r':
                if (js_addbuf_(jbuf, "\\r", 2) == -1) {
                    return -1;
                }

                break;
            case '\\':
                if (js_addbuf_(jbuf, "\\\\", 2) == -1) {
                    return -1;
                }

                break;
        } /* switch */
    }

    return 0;
}         /* js_escape_string_ */

static int
js_string_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    const char * str;

    if (lz_unlikely(json == NULL)) {
        return -1;
    }

    if (json->type != lz_json_vtype_string) {
        return -1;
    }

    str = json->string;

    if ((str = json->string) == NULL) {
        return -1;
    }

    if (js_addbuf_(jbuf, "\"", 1) == -1) {
        return -1;
    }

    if (jbuf->escape == true) {
        if (js_escape_string_(str, json->slen, jbuf) == -1) {
            return -1;
        }
    }

    return js_addbuf_(jbuf, "\"", 1);
}

static int
js_boolean_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    if (lz_unlikely(json == NULL)) {
        return -1;
    }

    if (json->type != lz_json_vtype_bool) {
        return -1;
    }

    return js_addbuf_printf_(jbuf, "%s",
                             js_get_boolean_(json) == true ? "true" : "false");
}

static int
js_null_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    if (lz_unlikely(json == NULL)) {
        return -1;
    }

    if (json->type != lz_json_vtype_null) {
        return -1;
    }

    return js_addbuf_printf_(jbuf, "null");
}

static int
js_array_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    lz_tailq      * array;
    lz_tailq_elem * elem;
    lz_tailq_elem * temp;

    if (lz_unlikely(!json || !jbuf)) {
        return -1;
    }

    if (json->type != lz_json_vtype_array) {
        return -1;
    }

    array = json->array;

    if (js_addbuf_(jbuf, "[", 1) == -1) {
        return -1;
    }

    for (elem = lz_tailq_first(array); elem; elem = temp)
    {
        lz_json * val;

        if (!(val = (lz_json *)lz_tailq_elem_data(elem))) {
            return -1;
        }

        if (js_json_to_buffer_(val, jbuf) == -1) {
            return -1;
        }

        if ((temp = lz_tailq_next(elem))) {
            if (js_addbuf_(jbuf, ",", 1) == -1) {
                return -1;
            }
        }
    }

    if (js_addbuf_(jbuf, "]", 1) == -1) {
        return -1;
    }

    return 0;
} /* js_array_to_buffer_ */

static int
js_object_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    lz_kvmap     * object;
    lz_kvmap_ent * ent;
    lz_kvmap_ent * temp;

    if (lz_unlikely(json == NULL)) {
        return -1;
    }

    if (json->type != lz_json_vtype_object) {
        return -1;
    }

    object = json->object;

    if (js_addbuf_(jbuf, "{", 1) == -1) {
        return -1;
    }

    for (ent = lz_kvmap_first(object); ent; ent = temp)
    {
        const char * key;
        lz_json    * val;

        if (!(key = lz_kvmap_ent_key(ent))) {
            return -1;
        }

        if (!(val = (lz_json *)lz_kvmap_ent_val(ent))) {
            return -1;
        }

         #ifdef LZ_JSON_OMIT_EMPTY
        if (js_get_size_(val) == 0) {
            temp = lz_kvmap_next(ent);
            continue;
        }

  #endif


        if (js_addbuf_(jbuf, "\"", 1) == -1) {
            return -1;
        }

        if (js_addbuf_(jbuf, key, lz_kvmap_ent_get_klen(ent)) == -1) {
            return -1;
        }

        if (js_addbuf_(jbuf, "\":", 2) == -1) {
            return -1;
        }

        if (js_json_to_buffer_(val, jbuf) == -1) {
            return -1;
        }

        if ((temp = lz_kvmap_next(ent))) {
            if (js_addbuf_(jbuf, ",", 1) == -1) {
                return -1;
            }
        }
    }

    if (js_addbuf_(jbuf, "}", 1) == -1) {
        return -1;
    }

    return 0;
} /* js_object_to_buffer_ */

static lz_json *
js_parse_value_(const char * data, size_t len, size_t * n_read)
{
    if (data == NULL || len == 0) {
        return NULL;
    }

    switch (data[0]) {
        case '"':
            return js_parse_string_(data, len, n_read);
        case '{':
            return js_parse_object_(data, len, n_read);
        case '[':
            return js_parse_array_(data, len, n_read);
        default:
            if (isdigit(data[0])) {
                return js_parse_number_(data, len, n_read);
            }

            switch (*data) {
                case 't':
                case 'f':
                    return js_parse_boolean_(data, len, n_read);
                case 'n':
                    return js_parse_null_(data, len, n_read);
            }
    } /* switch */

    /* *n_read = 0; */
    return NULL;
}

static int
js_json_to_buffer_(lz_json * json, struct __jbuf * jbuf)
{
    switch (json->type) {
        case lz_json_vtype_number:
            return js_number_to_buffer_(json, jbuf);
        case lz_json_vtype_array:
            return js_array_to_buffer_(json, jbuf);
        case lz_json_vtype_object:
            return js_object_to_buffer_(json, jbuf);
        case lz_json_vtype_string:
            return js_string_to_buffer_(json, jbuf);
        case lz_json_vtype_bool:
            return js_boolean_to_buffer_(json, jbuf);
        case lz_json_vtype_null:
            return js_null_to_buffer_(json, jbuf);
        default:
            return -1;
    }

    return 0;
}

static ssize_t
js_to_buffer_(lz_json * json, char * buf, size_t buf_len)
{
    struct __jbuf jbuf = {
        .buf     = buf,
        .buf_idx = 0,
        .written = 0,
        .buf_len = buf_len,
        .dynamic = 0,
        .escape  = true
    };

    if (js_json_to_buffer_(json, &jbuf) == -1) {
        return -1;
    }

    return jbuf.written;
}

static char *
js_to_buffer_alloc_(lz_json * json, size_t * len)
{
    struct __jbuf jbuf = {
        .buf     = NULL,
        .buf_idx = 0,
        .written = 0,
        .buf_len = 0,
        .dynamic = 1,
        .escape  = true
    };

    if (!json || !len) {
        return NULL;
    }

    if (js_json_to_buffer_(json, &jbuf) == -1) {
        lz_safe_free(jbuf.buf, free);
        return NULL;
    }

    *len = jbuf.written;

    return jbuf.buf;
}

static void
js_print_(FILE * out, lz_json * json)
{
    size_t len;
    char * buf;

    if ((buf = js_to_buffer_alloc_(json, &len)) == NULL) {
        fprintf(out, "{\"error\":%d}\n", len);
        return;
    }

    fprintf(out, "%s\n", buf);

    free(buf);
}

static int
js_number_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (j1->type != lz_json_vtype_number) {
        return -1;
    }

    if (j2->type != lz_json_vtype_number) {
        return -1;
    }

    if (js_get_number_(j1) != js_get_number_(j2)) {
        return -1;
    }

    return 0;
}

static int
js_array_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    lz_tailq      * j1_array;
    lz_tailq      * j2_array;
    lz_tailq_elem * elem;
    lz_tailq_elem * temp;
    int             idx;

    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (!(j1_array = js_get_array_(j1))) {
        return -1;
    }

    if (!(j2_array = js_get_array_(j2))) {
        return -1;
    }

    idx = 0;

    for (elem = lz_tailq_first(j1_array); elem; elem = temp)
    {
        lz_json * j1_val;
        lz_json * j2_val;

        j1_val = (lz_json *)lz_tailq_elem_data(elem);
        j2_val = (lz_json *)lz_tailq_get_at_index(j2_array, idx);

        if (j1_val && !j2_val) {
            return -1;
        }

        if (j2_val && !j1_val) {
            return -1;
        }

        if (js_compare_(j1_val, j2_val, cb) == -1) {
            return -1;
        }

        idx += 1;

        temp = lz_tailq_next(elem);
    }

    return 0;
} /* _lz_j_array_compare */

static int
js_object_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    lz_kvmap     * j1_map;
    lz_kvmap     * j2_map;
    lz_kvmap_ent * ent;
    lz_kvmap_ent * temp;

    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (!(j1_map = js_get_object_(j1))) {
        return -1;
    }

    if (!(j2_map = js_get_object_(j2))) {
        return -1;
    }

    for (ent = lz_kvmap_first(j1_map); ent; ent = temp)
    {
        const char * key;
        lz_json    * j1_val;
        lz_json    * j2_val;

        if (!(key = lz_kvmap_ent_key(ent))) {
            return -1;
        }

        if (!(j1_val = (lz_json *)lz_kvmap_ent_val(ent))) {
            return -1;
        }

        if (cb && (cb)(key, j1_val) == 1) {
            /* the key filter callback returned 1, which means we can ignore the
             * comparison of this field.
             */
            temp = lz_kvmap_next(ent);
            continue;
        }

        if (!(j2_val = (lz_json *)lz_kvmap_find(j2_map, key))) {
            return -1;
        }

        if (js_compare_(j1_val, j2_val, cb) == -1) {
            return -1;
        }

        temp = lz_kvmap_next(ent);
    }

    return 0;
} /* _lz_j_object_compare */

static int
js_string_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    const char * j1_str;
    const char * j2_str;

    if (!(j1_str = js_get_string_(j1))) {
        return -1;
    }

    if (!(j2_str = js_get_string_(j2))) {
        return -1;
    }

    if (strcmp(j1_str, j2_str)) {
        return -1;
    }

    return 0;
}

static int
js_boolean_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    if (!j1 || !j2) {
        return -1;
    }

    if (j1->type != lz_json_vtype_bool) {
        return -1;
    }

    if (j2->type != lz_json_vtype_bool) {
        return -1;
    }

    if (js_get_boolean_(j1) != js_get_boolean_(j2)) {
        return -1;
    }

    return 0;
}

static int
js_null_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    if (lz_unlikely(!j1 || !j2)) {
        return -1;
    }

    if (j1->type != lz_json_vtype_null || j2->type != lz_json_vtype_null) {
        return -1;
    }

    return 0;
}

static int
js_compare_(lz_json * j1, lz_json * j2, lz_json_key_filtercb cb)
{
    if (lz_unlikely(j1 == NULL || j2 == NULL)) {
        return -1;
    }

    if (j1->type != j2->type) {
        return -1;
    }

    if (js_get_size_(j1) != js_get_size_(j2)) {
        return -1;
    }

    switch (j1->type) {
        case lz_json_vtype_number:
            return js_number_compare_(j1, j2, cb);
        case lz_json_vtype_array:
            return js_array_compare_(j1, j2, cb);
        case lz_json_vtype_object:
            return js_object_compare_(j1, j2, cb);
        case lz_json_vtype_string:
            return js_string_compare_(j1, j2, cb);
        case lz_json_vtype_bool:
            return js_boolean_compare_(j1, j2, cb);
        case lz_json_vtype_null:
            return js_null_compare_(j2, j2, cb);
        default:
            return -1;
    }

    return 0;
}

int
lz_json_init(void)
{
    if (lz_unlikely(__js_heap == NULL)) {
        if (!(__js_heap = lz_heap_new(sizeof(lz_json), 1024))) {
            return -1;
        }
    }

    return 0;
} __attribute__((constructor(101)));

lz_alias(js_string_new_len_, lz_json_string_new_len);
lz_alias(js_boolean_new_, lz_json_boolean_new);
lz_alias(js_object_new_, lz_json_object_new);
lz_alias(js_string_new_, lz_json_string_new);
lz_alias(js_number_new_, lz_json_number_new);
lz_alias(js_array_new_, lz_json_array_new);
lz_alias(js_null_new_, lz_json_null_new);
lz_alias(js_free_, lz_json_free);

lz_alias(js_get_array_index_, lz_json_get_array_index);
lz_alias(js_get_null_, lz_json_get_null);
lz_alias(js_get_type_, lz_json_get_type);
lz_alias(js_get_size_, lz_json_get_size);
lz_alias(js_get_path_, lz_json_get_path);

lz_alias(js_parse_boolean_, lz_json_parse_boolean);
lz_alias(js_parse_string_, lz_json_parse_string);
lz_alias(js_parse_number_, lz_json_parse_number);
lz_alias(js_parse_array_, lz_json_parse_array);
lz_alias(js_parse_file_, lz_json_parse_file);
lz_alias(js_parse_null_, lz_json_parse_null);
lz_alias(js_parse_buf_, lz_json_parse_buf);

lz_alias(js_object_add_klen_, lz_json_object_add_klen);
lz_alias(js_object_add_, lz_json_object_add);
lz_alias(js_array_add_, lz_json_array_add);
lz_alias(js_add_, lz_json_add);
lz_alias(js_to_buffer_alloc_, lz_json_to_buffer_alloc);
lz_alias(js_to_buffer_, lz_json_to_buffer);
lz_alias(js_compare_, lz_json_compare);
lz_alias(js_print_, lz_json_print);
