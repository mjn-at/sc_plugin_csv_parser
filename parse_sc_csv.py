import csv
import argparse
import io


def plugin_64784_parser(input_file):
    output = []
    errors = []

    with open(input_file) as csv_file:
        csv_file_dict = csv.DictReader(csv_file)
        for row in csv_file_dict:
            if row["DNS Name"] != "":
                plugin_text = row["Plugin Text"]
                plugin_text_list = plugin_text.split("\n")
                plugin_text_list_sanitized = []

                for entry in plugin_text_list:
                    plugin_text_list_sanitized.append(entry.split(" : "))

                # @TODO: check line-count and read all lines in

                if len(plugin_text_list_sanitized) == 8:
                    installed_version = plugin_text_list_sanitized[4]
                    install_path = plugin_text_list_sanitized[5]
                    instance = plugin_text_list_sanitized[6]
                    recommend_min_version = plugin_text_list_sanitized[7]

                    output.append({"hostname": row["DNS Name"], "ip": row["IP Address"], "lastseen": row["Last Observed"], "instance": instance[1], "installed_version": installed_version[1], "install_path": install_path[1], "recommend_min_version": recommend_min_version[1]})

                elif len(plugin_text_list_sanitized) == 13:
                    installed_version = plugin_text_list_sanitized[9]
                    install_path = plugin_text_list_sanitized[10]
                    instance = plugin_text_list_sanitized[11]
                    recommend_min_version = plugin_text_list_sanitized[12]

                    output.append({"hostname": row["DNS Name"], "ip": row["IP Address"], "lastseen": row["Last Observed"], "instance": instance[1], "installed_version": installed_version[1], "install_path": install_path[1], "recommend_min_version": recommend_min_version[1]})

                elif len(plugin_text_list_sanitized) == 18:
                    installed_version = plugin_text_list_sanitized[14]
                    install_path = plugin_text_list_sanitized[15]
                    instance = plugin_text_list_sanitized[16]
                    recommend_min_version = plugin_text_list_sanitized[17]

                    output.append(
                        {"hostname": row["DNS Name"], "ip": row["IP Address"], "lastseen": row["Last Observed"],
                         "instance": instance[1], "installed_version": installed_version[1],
                         "install_path": install_path[1], "recommend_min_version": recommend_min_version[1]})

                else:
                    errors.append(plugin_text_list_sanitized)
            else:
                errors.append("Error: No DNS-Name - Data: "+ str(row))

    return output, errors

def plugin_63155_parser(input_file):
    output = []
    errors = []

    with open(input_file) as csv_file:
        csv_file_dict = csv.DictReader(csv_file)
        for row in csv_file_dict:
            if row["DNS Name"] != "":
                plugin_text = row["Plugin Text"]
                plugin_text_list = plugin_text.split("\n")
                plugin_text_list_sanitized = []

                for entry in plugin_text_list:
                    plugin_text_list_sanitized.append(entry.split(" : "))

                for i in range(2, len(plugin_text_list_sanitized)):
                    service_name = plugin_text_list_sanitized[i][0]
                    service_name_sanitized = service_name.split("  ")
                    service_path = plugin_text_list_sanitized[i][1]
                    output.append(
                        {"hostname": row["DNS Name"], "ip": row["IP Address"], "lastseen": row["Last Observed"],
                         "service_name": service_name_sanitized[1], "service_path": service_path})

            else:
                errors.append("Error: No DNS-Name - Data: "+ str(row))

    return output, errors

def plugin_65057_parser(input_file):
    output = []
    errors = []

    with open(input_file) as csv_file:
        csv_file_dict = csv.DictReader(csv_file)
        for row in csv_file_dict:
            if row["DNS Name"] != "":
                plugin_text = row["Plugin Text"]
                plugin_text_list = plugin_text.split("\n")
                plugin_text_list_sanitized = []

                for entry in plugin_text_list:
                    plugin_text_list_sanitized.append(entry.split(" : "))

                for i in range(1, len(plugin_text_list_sanitized)):
                    if plugin_text_list_sanitized[i][0] == "Path":
                        path = plugin_text_list_sanitized[i][1]
                        used_by_services = plugin_text_list_sanitized[i + 1][1]
                        file_write_allowed_for_groups = plugin_text_list_sanitized[i + 2][1]

                        if i == len(plugin_text_list_sanitized)-3:
                            full_control_of_dir_allowed_for_groups = ""
                        else:
                            if plugin_text_list_sanitized[i + 3][0] == "Full control of directory allowed for groups":
                                full_control_of_dir_allowed_for_groups = plugin_text_list_sanitized[i + 3][1]
                            else:
                                full_control_of_dir_allowed_for_groups = ""

                        output.append(
                            {"hostname": row["DNS Name"], "ip": row["IP Address"], "lastseen": row["Last Observed"],
                             "path": path, "used_by_services": used_by_services,
                             "file_write_allowed_for_groups": file_write_allowed_for_groups,
                             "full_control_of_dir_allowed_for_groups": full_control_of_dir_allowed_for_groups})
                    else:
                        pass
            else:
                errors.append("Error: No DNS-Name - Data: " + str(row))

    return output, errors

def generate_output(output_file, output_format, result_lst):
    resultstring = io.StringIO()

    if output_format == "csv":
        fieldnames = []
        for key in result_lst[0].keys():
            fieldnames.append(key)

        csv_generator = csv.DictWriter(resultstring, fieldnames=fieldnames)
        csv_generator.writeheader()

        for result_line in result_lst:
            csv_generator.writerow(result_line)
    elif output_format == "json":
        pass
        #@TODO: write option for json-output
    else:
        print("invalid output-format")

    if output_file == "stdout":
        print(resultstring.getvalue())
    else:
        with open(output_file, "w", newline='') as outputfile:
            outputfile.write(resultstring.getvalue())


def main():
    __authors__ = ["Martin J. Nagel"]
    __date__ = "2019-04-02"
    __description__ = "Converts multi-line Plugin-Text/-Output csv export from Tenable SecurityCenter into single-line format"
    __version__ = "1.0"

    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
    )

    available_output_formats = {"csv": csv}

    # positional arguments
    parser.add_argument("INPUT_FILE", help="Path to csv file")
    parser.add_argument("PLUGIN_ID", help="The Nessus Plugin-ID which data the csv file contains")

    # optional arguments
    parser.add_argument("--output-file", help="Path to output file")
    parser.add_argument("--output-format", help="Format for output file", choices=(available_output_formats.keys()), default="csv")
    parser.add_argument("--print-errors", help="prints the errors to stdout", choices=("True", "False"), default="False")
    parser.add_argument("-v", "--version", help="Display script version information", action="version", version=str(__version__))

    args = parser.parse_args()

    input_file = args.INPUT_FILE
    plugin_id = args.PLUGIN_ID
    if args.output_file:
        output_file = args.output_file
    if args.output_format:
        output_format = args.output_format
    if args.print_errors:
        print_errors = args.print_errors
    if not args.output_file:
        print("No output-file defined. Will write to stdout")
        output_file = "stdout"
    if not args.output_format:
        print("No output-format defined. Will use standard csv format")
        output_format = "csv"

    result_lst = []

    if plugin_id == "64784":
        result_lst, errors = plugin_64784_parser(input_file)
    elif plugin_id == "63155":
        result_lst, errors = plugin_63155_parser(input_file)
    elif plugin_id == "65057":
        result_lst, errors = plugin_65057_parser(input_file)
    else:
        print("Parser for Plugin-ID {} not implemented yet".format(plugin_id))

    if len(result_lst) != 0:
        generate_output(output_file, output_format, result_lst)
        print("\n\nErrors : {}".format(len(errors)))
        if print_errors == "True":
            for error in errors:
                print(error)

    else:
        print("no results")

if __name__ == "__main__":
    main()
