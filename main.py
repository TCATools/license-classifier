# -*- coding: utf-8 -*-
"""
license-classifier: license扫描分类工具
功能: 代码分析
用法: python3 main.py
"""

import os
import json
import subprocess
import sys
from license_type import *

CRITICAL = 1
HIGH = 2
MEDIUM = 3
LOW = 4
UNKNOWN = 5

Severity2Rule = {
    CRITICAL: "critical-risk",
    HIGH: "high-risk",
    MEDIUM: "medium-risk",
    LOW: "low-risk",
    UNKNOWN: "unknown-risk"
}

CONFIDENCE = 0.9

class LicenseClassifier(object):
    def __get_task_params(self):
        """获取需要任务参数
        :return:
        """
        task_request_file = os.environ.get("TASK_REQUEST")
        with open(task_request_file, "r") as rf:
            task_request = json.load(rf)
        task_params = task_request["task_params"]

        return task_params

    def run(self):
        """
        :return:
        """
        # 代码目录直接从环境变量获取
        source_dir = os.environ.get("SOURCE_DIR", None)
        print("[debug] source_dir: %s" % source_dir)
        # 其他参数从task_request.json文件获取
        task_params = self.__get_task_params()
        # 规则
        rules = task_params["rules"]
        # 过滤(默认过滤.git)
        re_exclude_path = task_params["path_filters"]["re_exclusion"]
        re_exclude = [".*/.git/.*"]
        re_exclude.extend(re_exclude_path)

        diff_file_json = os.environ.get("DIFF_FILES")
        if diff_file_json:  # 如果存在 DIFF_FILES, 说明是增量扫描, 直接获取增量文件列表
            print("[debug] get diff file: %s" % diff_file_json)
            with open(diff_file_json, "r") as rf:
                scan_files = json.load(rf)
        else:  # 未获取到环境变量,即全量扫描,遍历source_dir获取需要扫描的文件列表
            scan_files = [source_dir]
        if not scan_files:
            print("[error] To-be-scanned files is empty")
            return
        print("[debug] scan files: %s" % len(scan_files))

        error_output = "license.json"
        outfile = "output"
        fs = open(outfile, "w")

        # 三端环境
        if sys.platform in ("darwin",):
            cmd = ["./tool/mac/identify_license"]
        elif sys.platform in ("linux", "linux2"):
            cmd = ["./tool/linux/identify_license"]
        elif sys.platform in ("win32"):
            cmd = ["./tool/windows/identify_license.exe"]

        cmd = cmd + [
            "-headers",
            "-json",
            error_output
        ]
        if re_exclude:
            cmd.extend(["-ignore_paths_re", ",".join(re_exclude)])
        cmd.extend(scan_files)

        scan_cmd = " ".join(cmd)
        print("[debug] cmd: %s" % scan_cmd)
        subproc = subprocess.Popen(scan_cmd, stdout=fs, stderr=subprocess.STDOUT, shell=True)
        subproc.communicate()

        print("start data handle")
        result = []
        result_path = "result.json"
        # 数据处理
        try:
            with open(error_output, "r") as f:
                outputs_data = json.load(f)
        except:
            print("[error] Resulting file not found or cannot be loaded")
            with open(outfile, "r") as fs:
                print(fs.read())
            with open(result_path, "w") as fp:
                json.dump(result, fp, indent=2)
            return

        if outputs_data:
            for file_res in outputs_data:
                path = file_res["Filepath"]
                for item in file_res["Classifications"]:
                    confidence = item["Confidence"]
                    if confidence < CONFIDENCE:
                        continue
                    license = item['Name']
                    severity = self.license_severity(license)
                    rule_name = Severity2Rule.get(severity, None)
                    if rule_name not in rules:
                        continue
                    issue = {}
                    issue['path'] = path
                    issue['line'] = item['StartLine']
                    issue['column'] = 0
                    issue['msg'] = "License: %s; Confidence: %s; Link: https://spdx.org/licenses/%s.html" % (license, confidence, license)
                    issue['rule'] = rule_name
                    issue['refs'] = []
                    if issue != {}:
                        result.append(issue)

        with open(result_path, "w") as fp:
            json.dump(result, fp, indent=2)

    def license_severity(self, name):
        """
        根据license类型获取严重性
        """
        if name in forbiddenType:
            return CRITICAL
        elif name in restrictedType:
            return HIGH
        elif name in reciprocalType:
            return MEDIUM
        elif name in (noticeType + permissiveType + unencumberedType):
            return LOW
        else:
            return UNKNOWN


if __name__ == "__main__":
    print("-- start run tool ...")
    LicenseClassifier().run()
    print("-- end ...")
