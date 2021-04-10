#pragma once

#include <Windows.h>
#include <iostream>
#include <map>
#include <stdio.h>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>

#include "Helpers.h"

#define LOG_FNAME L"C:\\Windows\\Temp\\TiEtwAgent.txt"
#define YARA_ENABLED false

const std::string YARA_RULE_DIR{ "c:\\yara_rules" };
