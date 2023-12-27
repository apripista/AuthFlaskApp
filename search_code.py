import os
import re


def search_string_in_files(directory, search_string):
    result = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line_number, line in enumerate(lines, start=1):
                    if re.search(search_string, line):
                        result.append((file_path, line_number, line.strip()))

    return result


def search_and_replace_string_in_files(directory, search_string, replacement_string):
    result = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(file_path, "w", encoding="utf-8") as f:
                    for line_number, line in enumerate(lines, start=1):
                        if re.search(search_string, line):
                            # Replace the search string with the replacement string
                            line = re.sub(search_string, replacement_string, line)
                            result.append((file_path, line_number, line.strip()))
                        f.write(line)

    return result


if __name__ == "__main__":

    search_term = input("Enter the string to search: ")
    operation_choice = input("Choose operation (1: Search only, 2: Search and Replace): ")

    if operation_choice == "1":
        directory_to_search = input("Enter the directory to search in (press Enter for the current directory): ")
        if not directory_to_search:
            directory_to_search = "."
        result_lines = search_string_in_files(directory_to_search, search_term)
        if result_lines:
            print(f"Lines containing the search string '{search_term}':")
            for file_path, line_number, line_content in result_lines:
                print(f"{file_path}, Line {line_number}: {line_content}")
        else:
            print("No lines found containing the search string.")
    elif operation_choice == "2":
        replacement_term = input("Enter the string to replace with: ")
        directory_to_search = input("Enter the directory to search in (press Enter for the current directory): ")
        if not directory_to_search:
            directory_to_search = "."
        result_lines = search_and_replace_string_in_files(directory_to_search, search_term, replacement_term)
        if result_lines:
            print(f"Lines containing the search string '{search_term}' and replaced with '{replacement_term}':")
            for file_path, line_number, line_content in result_lines:
                print(f"{file_path}, Line {line_number}: {line_content}")
        else:
            print("No lines found containing the search string.")
    else:
        print("Invalid operation choice. Please enter either '1' or '2'.")
