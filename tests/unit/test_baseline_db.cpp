#include "baseline_db.hpp"

#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>
#include <unistd.h>

namespace {

AlertRecord Event(const std::string& id, const std::string& timestamp) {
    AlertRecord record;
    record.rule_id = id;
    record.rule_name = "rule " + id;
    record.severity = "high";
    record.file_path = "/tmp/" + id;
    record.event_type = "write";
    record.process_name = "test";
    record.pid = 123;
    record.user_name = "tester";
    record.uid = "1000";
    record.expected = "0644";
    record.actual = "0666";
    record.action_taken = "alert";
    record.recorded_at = timestamp;
    return record;
}

}  // namespace

int main() {
    const std::string db_path = "/tmp/baseline-guard-db-test-" + std::to_string(getpid()) + ".db";
    std::remove(db_path.c_str());

    {
        BaselineDB db(db_path);
        db.SaveAlert(Event("old", "20260801-00:00:00"));
        db.SaveAlert(Event("start", "2026-08-02T00:00:00"));
        db.SaveAlert(Event("middle", "2026-08-02 12:30:00"));
        db.SaveAlert(Event("tie-first", "20260803-23:59:59"));
        db.SaveAlert(Event("tie-second", "2026-08-03 23:59:59"));
        db.SaveAlert(Event("new", "2026-08-04 00:00:00"));

        const auto all = db.GetMonitorEvents();
        assert(all.size() == 6);
        assert(all[0].rule_id == "new");
        assert(all[1].rule_id == "tie-second");
        assert(all[2].rule_id == "tie-first");

        const auto range = db.GetMonitorEvents("2026-08-02 00:00:00", "2026-08-03 23:59:59");
        assert(range.size() == 4);
        assert(range.front().rule_id == "tie-second");
        assert(range.back().rule_id == "start");

        const auto from = db.GetMonitorEvents("2026-08-04 00:00:00", "");
        assert(from.size() == 1 && from[0].rule_id == "new");

        const auto through = db.GetMonitorEvents("", "2026-08-01 00:00:00");
        assert(through.size() == 1 && through[0].rule_id == "old");

        const auto empty = db.GetMonitorEvents("2026-09-01 00:00:00", "2026-09-02 23:59:59");
        assert(empty.empty());
    }

    std::remove(db_path.c_str());
    std::cout << "test_baseline_db: all tests passed\n";
    return 0;
}
