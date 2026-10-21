#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "zend_closures.h"

PHP_FUNCTION(get_addrs)
{
	zval *cl = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_ZVAL(cl)
	ZEND_PARSE_PARAMETERS_END();
	if (Z_TYPE_P(cl) != IS_OBJECT || Z_OBJ_HT_P(cl)->get_closure == NULL) {
		zend_argument_type_error(1, "must be a Closure");
		RETURN_THROWS();
	}

	array_init(return_value);
	add_assoc_long(return_value, "executor_globals",   (zend_long)(uintptr_t)&executor_globals);
	add_assoc_long(return_value, "EG_function_table",  (zend_long)(uintptr_t)&EG(function_table));
	add_assoc_long(return_value, "EG_class_table",     (zend_long)(uintptr_t)&EG(class_table));
	add_assoc_long(return_value, "EG_symbol_table",    (zend_long)(uintptr_t)&EG(symbol_table));
	add_assoc_long(return_value, "EG_zend_constants",  (zend_long)(uintptr_t)&EG(zend_constants));
	add_assoc_long(return_value, "closure_handlers",   (zend_long)(uintptr_t)Z_OBJ_P(cl)->handlers);
	add_assoc_long(return_value, "EG_minus_handlers",  (zend_long)((uintptr_t)&executor_globals - (uintptr_t)Z_OBJ_P(cl)->handlers));
	add_assoc_long(return_value, "EG_sym_off",         (zend_long)((uintptr_t)&EG(symbol_table) - (uintptr_t)&executor_globals));
	add_assoc_long(return_value, "EG_ft_off2",         (zend_long)((uintptr_t)&EG(function_table) - (uintptr_t)&executor_globals));
}

PHP_FUNCTION(get_dtor)
{
	zend_function *zf = zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("system"));
	array_init(return_value);
	add_assoc_long(return_value, "zval_ptr_dtor", (zend_long)(uintptr_t)&zval_ptr_dtor);
	add_assoc_long(return_value, "zif_system",    zf ? (zend_long)(uintptr_t)((zend_internal_function*)zf)->handler : 0);
	add_assoc_long(return_value, "zif_handler_off", (zend_long)((uintptr_t)&((zend_internal_function*)zf)->handler - (uintptr_t)zf));
}

static const zend_function_entry addrs_functions[] = {
	ZEND_FE(get_addrs, NULL)
	ZEND_FE(get_dtor, NULL)
	ZEND_FE_END
};

zend_module_entry addrs_module_entry = {
	STANDARD_MODULE_HEADER,
	"addrs",
	addrs_functions,
	NULL, NULL, NULL, NULL, NULL,
	PHP_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_ADDRS
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(addrs)
#endif
