#include "YaraInstance.h"

VOID compiler_log (
	int error_level,
	const char* file_name,
	int line_number,
	const char* message,
	void* user_data) {

	size_t size = strlen(message) + 1;
	wchar_t* out_message = new wchar_t[size];

	size_t outSize;
	mbstowcs_s(&outSize, out_message, size, message, size - 1);

	log_debug(out_message);
}

YaraInstance::YaraInstance() : compiler_(0), rules_(0) {
	yr_initialize();
	if (ERROR_SUCCESS != yr_compiler_create(&compiler_)) {
		log_debug(L"TiEtwAgent: Unable to create new Yara compiler");
		return;
	}
	yr_compiler_set_callback(compiler_, compiler_log, nullptr);
}

BOOL YaraInstance::include_rule(std::string rule_path) {
	std::string rule_string = ftostr(rule_path);
	if ("" != rule_string) {
		if (NULL == compiler_) {
			log_debug(L"An error occured while adding a rule, no compiler initialized\n");
			return false;
		}
		if (ERROR_SUCCESS != yr_compiler_add_string(compiler_, rule_string.c_str(), nullptr)) {
			log_debug(L"An error occured while adding a rule, compilation failed\n");
			return false;
		}
		return true;
	}
	return false;
}

BOOL YaraInstance::load_rules(const std::string& yara_dir) {
	using namespace boost;

	filesystem::path search_dir(yara_dir);
	filesystem::is_directory(search_dir);

	for (filesystem::directory_iterator it(search_dir); it!=filesystem::directory_iterator(); it++) {
		if (".yar" != it->path().extension())
			continue;
		if (!include_rule(it->path().string())) {
			log_debug(L"TiEtwAgent: An error occured while loading a single rule\n");
		}
	}

	if (ERROR_SUCCESS != yr_compiler_get_rules(compiler_, rules_)) {
		log_debug(L"TiEtwAgent: Unable to get Yara rules");
		return false;
	}
	return true;
}

BOOL YaraInstance::close() {
	if (ERROR_SUCCESS != yr_finalize()) {
		log_debug(L"An error occured while finishing\n");
		return false;
	}
	yr_compiler_destroy(compiler_);
	return true;
}