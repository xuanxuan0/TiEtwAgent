#pragma once

#include <yara.h>
#include <string>

#pragma comment (lib,"libyara64.lib")

class YaraInstance {
public:
	bool create_init();
	bool close();
	bool add_rule(const std::string& rule_string, const std::string& n);
	bool get_rules(YR_COMPILER* compiler, YR_RULES** rules);

private:
	YR_COMPILER* compiler_;
	YR_RULES** rules_;

};
