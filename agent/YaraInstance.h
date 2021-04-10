#pragma once

#include "TiEtwAgent.h"

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <yara.h>

#pragma comment (lib,"libyara64.lib")

class YaraInstance {
public:
	YaraInstance();
	BOOL close();
	BOOL load_rules(const std::string& file_name);
	BOOL include_rule(std::string rule_string);

private:
	YR_COMPILER* compiler_;
	YR_RULES** rules_;
};

