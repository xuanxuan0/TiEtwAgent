#include "YaraInstance.h"
#include "Helpers.h"

bool YaraInstance::create_init() {
	yr_initialize();
	if (yr_compiler_create(&compiler_) != 0) {
		log_debug(L"An error occured while creating a new compiler\n");
		return false;
	}
	return true;
}

bool YaraInstance::close() {
	if (yr_finalize() != 0) {
		log_debug(L"An error occured while finishing\n");
		return false;
	}
	yr_compiler_destroy(compiler_);
	return true;
}

bool YaraInstance::add_rule(const std::string& rule_string, const std::string& n) {
	if (NULL == compiler_) {
		log_debug(L"An error occured while adding a rule, no compiler initialized\n");
		return false;
	}
	if (yr_compiler_add_string(compiler_, rule_string.c_str(), n.c_str()) != 0) {
		log_debug(L"An error occured while adding a rule, compilation failed\n");
		return false;
	}
	return true;
}

bool YaraInstance::get_rules(YR_COMPILER* compiler, YR_RULES** rules) {
	if (yr_compiler_get_rules(compiler_, rules_) != 0) {
		log_debug(L"An error occured while getting compiled rules\n");
		return false;
	}
	return true;
}