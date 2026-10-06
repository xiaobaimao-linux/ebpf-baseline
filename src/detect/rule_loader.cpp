#include "rule_loader.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <filesystem>
#include <set>

#include "condition_parser.hpp"
#include "rule_engine.hpp"

namespace detect {

namespace {

bool is_priority_valid(const std::string &p) {
    return p == "critical" || p == "high" || p == "medium" || p == "low";
}

std::string err_at(const std::string &file, const YAML::Mark &mark, const std::string &reason) {
    return file + ":" + std::to_string(mark.line + 1) + ": " + reason;
}

bool load_file(const std::string &path, std::set<std::string> &names, std::vector<Rule> &out,
               std::string &err) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception &e) {
        err = path + ":" + std::to_string(e.mark.line + 1) + ": " + e.what();
        return false;
    }
    if (!root.IsSequence()) {
        err = err_at(path, root.Mark(), "规则文件顶层必须是规则列表");
        return false;
    }

    static const char *kRequired[] = {"rule",     "desc",   "condition", "output",
                                      "priority", "attack", "fpr_note",  "response"};

    for (const auto &item : root) {
        if (!item.IsMap()) {
            err = err_at(path, item.Mark(), "规则条目必须是 map");
            return false;
        }
        for (const char *key : kRequired) {
            if (!item[key]) {
                err = err_at(path, item.Mark(), std::string("缺少必填字段: ") + key);
                return false;
            }
        }

        Rule rule;
        rule.source_file = path;
        try {
            rule.name = item["rule"].as<std::string>();
            rule.desc = item["desc"].as<std::string>();
            rule.output_template = item["output"].as<std::string>();
            rule.priority = item["priority"].as<std::string>();
            rule.fpr_note = item["fpr_note"].as<std::string>();
            rule.response = item["response"].as<std::string>();
        } catch (const YAML::Exception &e) {
            err = err_at(path, e.mark, std::string("字段类型错误: ") + e.what());
            return false;
        }

        if (rule.name.empty()) {
            err = err_at(path, item["rule"].Mark(), "规则名不能为空");
            return false;
        }
        if (!names.insert(rule.name).second) {
            err = err_at(path, item["rule"].Mark(), "规则名全局重复: " + rule.name);
            return false;
        }
        if (!is_priority_valid(rule.priority)) {
            err =
                err_at(path, item["priority"].Mark(),
                       "非法 priority 值: " + rule.priority + "（枚举 critical/high/medium/low）");
            return false;
        }

        const YAML::Node &attack = item["attack"];
        if (!attack.IsSequence()) {
            err = err_at(path, attack.Mark(), "attack 必须是 ATT&CK 技术 ID 列表");
            return false;
        }
        for (const auto &t : attack) {
            try {
                rule.attack.push_back(t.as<std::string>());
            } catch (const YAML::Exception &e) {
                err = err_at(path, e.mark, "attack 列表元素必须是字符串");
                return false;
            }
        }

        const YAML::Node &cond_node = item["condition"];
        std::string cond_text;
        try {
            cond_text = cond_node.as<std::string>();
        } catch (const YAML::Exception &) {
            err = err_at(path, cond_node.Mark(), "condition 必须是字符串");
            return false;
        }
        std::string perr;
        rule.condition = ParseCondition(cond_text, perr);
        if (!rule.condition) {
            err = err_at(path, cond_node.Mark(), perr);
            return false;
        }

        // output 模板加载期校验（字段对照 schema 字段表；编译产物在引擎 Build 时重建）
        std::vector<TemplateSeg> segs;
        if (!ParseOutputTemplate(rule.output_template, segs, perr)) {
            err = err_at(path, item["output"].Mark(), perr);
            return false;
        }

        out.push_back(std::move(rule));
    }
    return true;
}

} // namespace

bool LoadRulesDir(const std::string &dir, std::vector<Rule> &out, std::string &err) {
    out.clear();
    err.clear();

    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        err = dir + ": 规则目录不存在或不是目录";
        return false;
    }

    std::vector<std::string> files;
    // 递归遍历（rules/examples/ 等子目录一并加载）
    for (const auto &entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
        if (!entry.is_regular_file())
            continue;
        const std::string ext = entry.path().extension().string();
        if (ext == ".yaml" || ext == ".yml")
            files.push_back(entry.path().string());
    }
    if (ec) {
        err = dir + ": 读取规则目录失败: " + ec.message();
        return false;
    }
    std::sort(files.begin(), files.end());

    std::set<std::string> names;
    for (const auto &f : files) {
        if (!load_file(f, names, out, err))
            return false;
    }
    return true;
}

} // namespace detect
