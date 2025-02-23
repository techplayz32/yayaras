import os
from datetime import datetime

output_file = "index.yar"
rules_folder = "rules"

current_date_formatted = datetime.now().strftime("%Y-%m-%d")

header_comment = f"""/*
    Combined YARA Rules Index
    Generated automatically on {current_date_formatted}
    This file includes all rules from the rules folder
    
    With kindness, 
    Made by techplayz32
*/
"""

try:
    rule_files = [f for f in os.listdir(rules_folder) if f.endswith(".yar")]

    if not rule_files:
        print("No .yar files found in the rules folder!")
        exit(1)

    rule_files.sort()

    includes = [f'include ".\\rules\\{filename}"' for filename in rule_files]
    file_content = header_comment + "\n" + "\n".join(includes)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(file_content)

    print(f"Successfully created {output_file} with {len(rule_files)} rules included")
    print("Included files:")
    for rule in rule_files:
        print(f"- {rule}")

except FileNotFoundError:
    print(f"Error: The folder '{rules_folder}' was not found!")
except PermissionError:
    print(
        f"Error: Permission denied when accessing '{rules_folder}' or writing to '{output_file}'"
    )
except Exception as e:
    print(f"An unexpected error occurred: {str(e)}")
