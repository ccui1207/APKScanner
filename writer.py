import os
import collections
from textwrap import TextWrapper

try:
    from androguard.core.analysis import analysis  # optional, kept for compatibility
except Exception:
    analysis = None

from constants import *

REPORT_OUTPUT = 'print_and_file'
DIRECTORY_REPORT_OUTPUT = "Reports/"


class Writer:
    def __init__(self):
        self.__package_information = {}
        self.__cache_output_detail_stream = []
        self.__output_dict_vector_result_information = {}
        self.__output_current_tag = ""
        self.__file_io_result_output_list = []
        self.__file_io_information_output_list = []

    def simplifyClassPath(self, class_name):
        if isinstance(class_name, str) and class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1]
        return class_name

    def show_xrefs_method_class_analysis_list(self, method_class_analysis_list, indention_space_count=0):
        for method_class_analysis in method_class_analysis_list:
            self.show_xrefs_method_class_analysis(method_class_analysis, indention_space_count)

    def show_xrefs_method_class_analysis(self, method_class_analysis, indention_space_count=0):
        dest_class_name = method_class_analysis.get_method().get_class_name()
        dest_name = method_class_analysis.get_method().get_name()
        dest_descriptor = method_class_analysis.get_method().get_descriptor()

        for _, source_method, idx in method_class_analysis.get_xref_from():
            self.write(
                "=> %s->%s%s (0x%x) ---> %s->%s%s" % (
                    source_method.get_class_name(),
                    source_method.get_name(),
                    source_method.get_descriptor(),
                    idx,
                    dest_class_name,
                    dest_name,
                    dest_descriptor,
                ),
                indention_space_count
            )

    def show_xrefs_class_analysis_list(self, class_analysis_list, indention_space_count=0):
        for class_analysis in class_analysis_list:
            self.show_xrefs_class_analysis(class_analysis, indention_space_count)

    def show_xrefs_class_analysis(self, class_analysis, indention_space_count=0):
        dest_class_name = class_analysis.name
        for source_class, _source_methods in class_analysis.get_xref_from().items():
            self.write("=> %s ---> %s" % (source_class.name, dest_class_name), indention_space_count)

    def show_Path(self, path, indention_space_count=0):
        self.write(
            "=> %s->%s%s (0x%x) ---> %s->%s%s" % (
                path['src_method'].get_class_name(),
                path['src_method'].get_name(),
                path['src_method'].get_descriptor(),
                path['idx'],
                path['dst_method'].get_class_name(),
                path['dst_method'].get_name(),
                path['dst_method'].get_descriptor(),
            ),
            indention_space_count
        )

    def show_Path_only_source(self, vm, path, indention_space_count=0):
        self.write(
            "=> %s->%s%s" % (
                path['src_method'].get_class_name(),
                path['src_method'].get_name(),
                path['src_method'].get_descriptor(),
            ),
            indention_space_count
        )

    def show_Paths(self, paths, indention_space_count=0):
        for path in paths:
            self.show_Path(path, indention_space_count)

    def startWriter(self, tag, level, summary, title_msg, special_tag=None, cve_number=""):
        self.completeWriter()
        self.__output_current_tag = tag

        assert tag is not None and level is not None and summary is not None and title_msg is not None, \
            '"tag", "level", "summary", "title_msg" should all have values.'

        info = {
            "level": level,
            "title": str(title_msg).rstrip('\n'),
            "summary": str(summary).rstrip('\n'),
            "count": 0,
        }

        if special_tag:
            assert isinstance(special_tag, list), "special_tag should be list"
            info["special_tag"] = special_tag

        if cve_number:
            assert isinstance(cve_number, str), "cve_number should be string"
            info["cve_number"] = cve_number

        self.__output_dict_vector_result_information[tag] = info

    def get_valid_encoding_utf8_string(self, utf8_string):
        if utf8_string is None:
            return b""
        if isinstance(utf8_string, bytes):
            try:
                return utf8_string.decode('unicode_escape').encode('utf8')
            except Exception:
                return utf8_string
        if isinstance(utf8_string, str):
            try:
                return utf8_string.encode('utf8')
            except Exception:
                return utf8_string.encode(errors='ignore')
        return str(utf8_string).encode('utf8', errors='ignore')

    def write(self, detail_msg, indention_space_count=0):
        self.__cache_output_detail_stream.append(str(detail_msg) + "\n")

    def get_packed_analyzed_results_for_mongodb(self):
        analyze_packed_result = self.getInf()
        if analyze_packed_result and self.get_analyze_status() == "success":
            analyze_packed_result["details"] = self.__output_dict_vector_result_information
            return analyze_packed_result
        return None

    def get_search_enhanced_packed_analyzed_results_for_mongodb(self):
        analyze_packed_result = self.getInf()
        if not analyze_packed_result or self.get_analyze_status() != "success":
            return None

        prepared_search_enhanced_result = []
        for tag, dict_information in self.__output_dict_vector_result_information.items():
            search_enhanced_result = {
                "vector": tag,
                "level": dict_information.get("level"),
                "analyze_engine_build": analyze_packed_result.get("analyze_engine_build"),
                "analyze_mode": analyze_packed_result.get("analyze_mode"),
                "package_name": analyze_packed_result.get("package_name"),
                "file_sha512": analyze_packed_result.get("file_sha512"),
                "signature_unique_analyze": analyze_packed_result.get("signature_unique_analyze"),
            }
            if "analyze_tag" in analyze_packed_result:
                search_enhanced_result["analyze_tag"] = analyze_packed_result["analyze_tag"]
            if "package_version_code" in analyze_packed_result:
                search_enhanced_result["package_version_code"] = analyze_packed_result["package_version_code"]
            prepared_search_enhanced_result.append(search_enhanced_result)

        return prepared_search_enhanced_result

    def getInf(self, key=None, default_value=None):
        if key is None:
            return self.__package_information

        if key in self.__package_information:
            value = self.__package_information[key]
            if value is None and default_value is not None:
                return default_value
            return value

        if default_value is not None:
            return default_value
        return None

    def writePlainInf(self, msg):
        self.__file_io_information_output_list.append(str(msg))

    def writeInf(self, key, value, extra_title, extra_print_original_title=False):
        if extra_print_original_title:
            print(str(extra_title))
            self.__file_io_information_output_list.append(str(extra_title))
        else:
            print(extra_title + ": " + str(value))
            self.__file_io_information_output_list.append(extra_title + ": " + str(value))
        self.__package_information[key] = value

    def writeInf_ForceNoPrint(self, key, value):
        self.__package_information[key] = value

    def update_analyze_status(self, status):
        self.writeInf_ForceNoPrint("analyze_status", status)

    def get_analyze_status(self):
        return self.getInf("analyze_status")

    def get_total_vector_count(self):
        if self.__output_dict_vector_result_information:
            return len(self.__output_dict_vector_result_information)
        return 0

    def completeWriter(self):
        if self.__cache_output_detail_stream and self.__output_current_tag != "":
            current_tag = self.__output_current_tag
            if current_tag in self.__output_dict_vector_result_information:
                self.__output_dict_vector_result_information[current_tag]["count"] = len(
                    self.__cache_output_detail_stream
                )

                output_string = "".join(str(line) for line in self.__cache_output_detail_stream)
                self.__output_dict_vector_result_information[current_tag]["vector_details"] = output_string

                try:
                    self.__output_dict_vector_result_information[current_tag]["title"] = \
                        self.__output_dict_vector_result_information[current_tag]["title"]
                except KeyError:
                    if DEBUG:
                        print('[KeyError on "__output_dict_vector_result_information"]')

            self.__output_current_tag = ""
            self.__cache_output_detail_stream[:] = []

    def is_dict_information_has_cve_number(self, dict_information):
        return bool(dict_information and dict_information.get("cve_number"))

    def is_dict_information_has_special_tag(self, dict_information):
        return bool(dict_information and dict_information.get("special_tag"))

    def __sort_by_level(self, item):
        try:
            _tag, value = item
            level = value.get("level")
            if level == LEVEL_CRITICAL:
                return 5
            elif level == LEVEL_WARNING:
                return 4
            elif level == LEVEL_NOTICE:
                return 3
            elif level == LEVEL_INFO:
                return 2
            else:
                return 1
        except Exception:
            return 1

    def append_to_file_io_information_output_list(self, line):
        self.__file_io_information_output_list.append(line)

    def save_result_to_file(self, output_file_path, args):
        if not self.__file_io_result_output_list:
            self.load_to_output_list(args)

        try:
            with open(output_file_path, "w", encoding="utf-8", errors="ignore") as f:
                if self.__file_io_information_output_list:
                    for line in self.__file_io_information_output_list:
                        f.write(line + "\n")

                for line in self.__file_io_result_output_list:
                    f.write(line + "\n")

            print("<<< Analysis report is generated: " + os.path.abspath(output_file_path) + " >>>")
            print("")
            return True
        except IOError:
            if DEBUG:
                print("[Error on writing output file to disk]")
            return False

    def show(self, args):
        if not self.__file_io_result_output_list:
            self.load_to_output_list(args)

        if self.__file_io_result_output_list:
            for line in self.__file_io_result_output_list:
                print(line)

    def output(self, line):
        self.__file_io_result_output_list.append(line)

    def output_and_force_print_console(self, line):
        self.__file_io_result_output_list.append(line)
        print(line)

    def load_to_output_list(self, args):
        self.__file_io_result_output_list[:] = []

        wrapperTitle = TextWrapper(
            initial_indent=' ' * 11,
            subsequent_indent=' ' * 11,
            width=args.line_max_output_characters
        )
        wrapperDetail = TextWrapper(
            initial_indent=' ' * 15,
            subsequent_indent=' ' * 20,
            width=args.line_max_output_characters
        )

        sorted_output_dict_result_information = collections.OrderedDict(
            sorted(self.__output_dict_vector_result_information.items())
        )

        for tag, dict_information in sorted(
            list(sorted_output_dict_result_information.items()),
            key=self.__sort_by_level,
            reverse=True
        ):
            extra_field = ""

            if self.is_dict_information_has_special_tag(dict_information):
                for i in dict_information["special_tag"]:
                    extra_field += "<" + str(i) + ">"

            if self.is_dict_information_has_cve_number(dict_information):
                extra_field += "<#" + str(dict_information["cve_number"]) + "#>"

            if args.show_vector_id:
                self.output(
                    "[%s] %s %s (Vector ID: %s):" % (
                        dict_information["level"],
                        extra_field,
                        dict_information["summary"],
                        tag
                    )
                )
            else:
                self.output(
                    "[%s] %s %s:" % (
                        dict_information["level"],
                        extra_field,
                        dict_information["summary"]
                    )
                )

            for line in str(dict_information["title"]).split('\n'):
                self.output(wrapperTitle.fill(line))

            if "vector_details" in dict_information:
                for line in str(dict_information["vector_details"]).split('\n'):
                    if line != "":
                        self.output(wrapperDetail.fill(line))

            self.output("------------------------------------------------------------")

        stopwatch_total_elapsed_time = self.getInf("time_total")
        stopwatch_analyze_time = self.getInf("time_analyze")
        stopwatch_hacker_debuggable = self.getInf("time_hacker_debuggable_check")

        if stopwatch_total_elapsed_time and stopwatch_analyze_time:
            if REPORT_OUTPUT == "file":
                self.output_and_force_print_console(
                    "AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs"
                )
                self.output_and_force_print_console(
                    "HACKER_DEBUGGABLE_CHECK elapsed time: " + str(stopwatch_hacker_debuggable) + " secs"
                )
                self.output_and_force_print_console(
                    "Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs"
                )
            else:
                self.output("AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
                self.output(
                    "HACKER_DEBUGGABLE_CHECK elapsed time: " + str(stopwatch_hacker_debuggable) + " secs"
                )
                self.output("Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")

        if getattr(args, "store_analysis_result_in_db", False):
            analysis_tips_output = "("
            if getattr(args, "analyze_engine_build", None):
                analysis_tips_output += "analyze_engine_build: " + str(args.analyze_engine_build) + ", "
            if getattr(args, "analyze_tag", None):
                analysis_tips_output += "analyze_tag: " + str(args.analyze_tag) + ", "
            if analysis_tips_output.endswith(", "):
                analysis_tips_output = analysis_tips_output[:-2]
            analysis_tips_output += ")"

            if REPORT_OUTPUT == "file":
                self.output_and_force_print_console(
                    "<<< Analysis result has stored into database " + analysis_tips_output + " >>>"
                )
            else:
                self.output(
                    "<<< Analysis result has stored into database " + analysis_tips_output + " >>>"
                )
