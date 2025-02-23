# ===--- run ---------------------------------------------------------------------------------------------===
#
#  This source file is part of the YAYARAS open source project.
#
#  Copyright (c) 2025 - Present
#  - techplayz32,
#  - The YARA Authors,
#  - The pyinstxtractor Authors (extremecoders-re, maximevince, 2press)
#  and contributors of YAYARAS.
#
#  Licensed under the GNU General Public License v3 (GPLv3).
#
#  This project incorporates code from:
#  - YARA (VirusTotal), licensed under the BSD 3-Clause License.
#  - pyinstxtractor (extremecoders-re), licensed under the GPL v3.
#
#  You are free to modify and distribute this source code under the terms of the GPLv3.
#
# ===-----------------------------------------------------------------------------------------------------===

import argparse
import concurrent.futures
import logging
import os
import subprocess
from typing import List, Optional

import yara

INTERESTING_EXTENSIONS = {
    ".exe",
    ".dll",
    ".vbs",
    ".ps1",
    ".js",
    ".hta",
    ".bat",
    ".cmd",
    ".scr",
    ".pif",
    ".lnk",
    ".cpl",
    ".ocx",
    ".ax",
    ".sys",
    ".drv",
    ".so",
    ".dylib",
    ".efi",
    ".rtf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".jar",
    ".war",
    ".ear",
    ".zip",
    ".rar",
    ".7z",
    ".gzip",
    ".tar",
    ".bzip2",
    ".xz",
    ".cab",
    ".chm",
    ".hlp",
    ".rtf",
    ".swf",
    ".flv",
    ".mpeg",
    ".mpg",
    ".avi",
    ".wmv",
    ".mov",
    ".mp4",
    ".mkv",
    ".webm",
    ".vob",
    ".iso",
    ".img",
    ".vmdk",
    ".vdi",
    ".ova",
    ".ovf",
    ".xar",
    ".lzh",
    ".lha",
    ".sea",
    ".hqx",
    ".bin",
    ".dat",
    ".class",
    ".pyc",
    ".pyo",
    ".rbc",
    ".jsc",
    ".dex",
    ".apk",
    ".ipa",
    ".plist",
    ".cfg",
    ".ini",
    ".conf",
    ".inf",
    ".reg",
    ".psd1",
    ".psm1",
    ".ps1xml",
    ".xml",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
    ".db",
    ".sqlite",
    ".mdb",
    ".ldb",
    ".sdb",
    ".pcap",
    ".cap",
    ".evtx",
    ".evt",
    ".log",
    ".dump",
    ".mem",
    ".core",
    ".dmp",
    ".pwd",
    ".password",
    ".key",
    ".crt",
    ".cer",
    ".pem",
    ".kdb",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".url",
    ".desktop",
    ".action",
    ".appref-ms",
    ".application",
    ".gadget",
    ".msi",
    ".msp",
    ".mst",
    ".shb",
    ".theme",
    ".xbap",
    ".xll",
    ".xnk",
    ".appcontent-ms",
    ".settingcontent-ms",
    ".searchconnector-ms",
    ".library-ms",
    ".printerexport",
    ".infopathxml",
    ".one",
    ".onepkg",
    ".oxps",
    ".p7b",
    ".p7c",
    ".p7r",
    ".spx",
    ".udl",
    ".accda",
    ".accdb",
    ".accdc",
    ".accde",
    ".accdf",
    ".accdp",
    ".app",
    ".asax",
    ".ascx",
    ".ashx",
    ".asmx",
    ".browser",
    ".cdx",
    ".ceam",
    ".cel",
    ".config",
    ".contact",
    ".cshtml",
    ".cshtm",
    ".dcr",
    ".deploy",
    ".design",
    ".disco",
    ".eddx",
    ".eot",
    ".group",
    ".hdp",
    ".hta",
    ".iim",
    ".its",
    ".jnlp",
    ".lck",
    ".library-ms",
    ".maf",
    ".mapimail",
    ".master",
    ".mdpolicy",
    ".mhtml",
    ".mscx",
    ".mscz",
    ".mslzs",
    ".msu",
    ".mui",
    ".natvis",
    ".nsp",
    ".ops",
    ".osdx",
    ".pdl",
    ".pfx",
    ".plink",
    ".policy",
    ".printersettings",
    ".ps1e",
    ".ps2",
    ".ps2xml",
    ".psc2",
    ".psd",
    ".resources",
    ".ruleset",
    ".settings",
    ".skin",
    ".slk",
    ".soap",
    ".sor",
    ".stm",
    ".svc",
    ".tag",
    ".testsettings",
    ".thmx",
    ".tlb",
    ".trm",
    ".udcx",
    ".usage",
    ".vb",
    ".vbe",
    ".vbscript",
    ".vscontent",
    ".vsdisco",
    ".vspolicy",
    ".vspscc",
    ".vssscc",
    ".vstemplate",
    ".vsix",
    ".vsmdi",
    ".vsmproj",
    ".vxml",
    ".webapp",
    ".website",
    ".wflow",
    ".widget",
    ".workflow",
    ".whtt",
    ".wpy",
    ".ws",
    ".wsc",
    ".wsf",
    ".wsh",
    ".xaml",
    ".xap",
    ".xbap",
    ".xdr",
    ".xht",
    ".xlb",
    ".xlc",
    ".xld",
    ".xlk",
    ".xll",
    ".xlm",
    ".xlsb",
    ".xlt",
    ".xltm",
    ".xltx",
    ".xlw",
    ".xps",
    ".xsd",
    ".xsf",
    ".xsl",
    ".xslt",
    ".xsn",
    ".xtp",
    ".zargo",
    ".zxip",
}

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class RuleLoader:
    """
    Handles loading and compiling YARA rules from files or directories.
    """

    def __init__(self) -> None:
        """
        Initializes the RuleLoader.
        """
        self.rules: Optional[yara.Rules] = None

    def load_rules_from_file(self, rule_file_path: str) -> None:
        """
        Loads YARA rules from a single file.

        Args:
            rule_file_path (str): Path to the YARA rules file.

        Raises:
            FileNotFoundError: If the rule file is not found.
            yara.SyntaxError: If there is a syntax error in the YARA rules.
            yara.Error: For other YARA related errors.
        """
        logger.info(f"Loading YARA rules from file: {rule_file_path}")
        if not os.path.exists(rule_file_path):
            logger.error(f"Rule file not found: {rule_file_path}")
            raise FileNotFoundError(f"Rule file not found: {rule_file_path}")
        try:
            self.rules = yara.compile(filepath=rule_file_path)
            logger.info(f"Successfully loaded rules from: {rule_file_path}")
        except yara.SyntaxError as e:
            logger.error(f"YARA rule syntax error in {rule_file_path}: {e}")
            raise
        except yara.Error as e:
            logger.error(f"Error compiling YARA rules from {rule_file_path}: {e}")
            raise

    def load_rules_from_directory(self, rule_dir_path: str) -> None:
        """
        Loads YARA rules from all files in a directory.

        Args:
            rule_dir_path (str): Path to the directory containing YARA rules.

        Raises:
            FileNotFoundError: If the rule directory is not found.
            ValueError: If no rule files are found in the directory.
            yara.SyntaxError: If there is a syntax error in any YARA rule file.
            yara.Error: For other YARA related errors.
        """
        logger.info(f"Loading YARA rules from directory: {rule_dir_path}")
        if not os.path.isdir(rule_dir_path):
            logger.error(f"Rule directory not found: {rule_dir_path}")
            raise FileNotFoundError(f"Rule directory not found: {rule_dir_path}")
        rule_files = [
            os.path.join(rule_dir_path, f)
            for f in os.listdir(rule_dir_path)
            if os.path.isfile(os.path.join(rule_dir_path, f))
        ]
        if not rule_files:
            logger.warning(f"No rule files found in directory: {rule_dir_path}")
            raise ValueError(f"No rule files found in directory: {rule_dir_path}")
        try:
            self.rules = yara.compile(filepaths=rule_files)
            logger.info(f"Successfully loaded rules from directory: {rule_dir_path}")
        except yara.SyntaxError as e:
            logger.error(f"YARA rule syntax error in directory {rule_dir_path}: {e}")
            raise
        except yara.Error as e:
            logger.error(
                f"Error compiling YARA rules from directory {rule_dir_path}: {e}"
            )
            raise

    def get_rules(self) -> yara.Rules:
        """
        Returns the compiled YARA rules.

        Returns:
            yara.Rules: Compiled YARA rules object.

        Raises:
            ValueError: If rules are not loaded yet.
        """
        if self.rules is None:
            logger.error("YARA rules not loaded yet.")
            raise ValueError(
                "YARA rules not loaded. Call load_rules_from_file or load_rules_from_directory first."
            )
        return self.rules


class Scanner:
    """
    Handles scanning files, directories, and memory buffers using YARA rules.
    """

    def __init__(self, rules: yara.Rules) -> None:
        """
        Initializes the Scanner with compiled YARA rules.

        Args:
            rules (yara.Rules): Compiled YARA rules object.
        """
        self.rules = rules

    def scan_file(self, file_path: str) -> Optional[List[yara.Match]]:
        """
        Scans a single file for YARA rule matches.

        Args:
            file_path (str): Path to the file to scan.

        Returns:
            Optional[List[yara.Match]]: A list of YARA match objects if matches are found, otherwise None.

        Raises:
            FileNotFoundError: If the file to scan is not found.
            PermissionError: If there is a permission error accessing the file.
            yara.Error: For YARA scanning errors.
        """
        logger.debug(f"Scanning file: {file_path}")
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
        if not os.access(file_path, os.R_OK):
            logger.error(f"Permission error accessing file: {file_path}")
            raise PermissionError(f"Permission error accessing file: {file_path}")
        try:
            matches = self.rules.match(file_path)
            if matches:
                logger.info(f"Matches found in file: {file_path}")
                return matches
            else:
                logger.debug(f"No matches in file: {file_path}")
                return None
        except yara.Error as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            raise

    def scan_memory(self, memory_buffer: bytes) -> Optional[List[yara.Match]]:
        """
        Scans a memory buffer for YARA rule matches.

        Args:
            memory_buffer (bytes): The memory buffer to scan.

        Returns:
            Optional[List[yara.Match]]: A list of YARA match objects if matches are found, otherwise None.

        Raises:
            TypeError: If the memory buffer is not bytes.
            yara.Error: For YARA scanning errors.
        """
        logger.debug("Scanning memory buffer")
        if not isinstance(memory_buffer, bytes):
            logger.error("Memory buffer must be bytes.")
            raise TypeError("Memory buffer must be bytes.")
        try:
            matches = self.rules.match(data=memory_buffer)
            if matches:
                logger.info("Matches found in memory buffer.")
                return matches
            else:
                logger.debug("No matches in memory buffer.")
                return None
        except yara.Error as e:
            logger.error(f"Error scanning memory buffer: {e}")
            raise

    def scan_directory(
        self,
        directory_path: str,
        recursive: bool = False,
        use_multithreading: bool = False,
    ) -> List[dict]:
        """
        Scans files in a directory, optionally recursively, for YARA rule matches.

        Args:
            directory_path (str): Path to the directory to scan.
            recursive (bool): Whether to scan subdirectories recursively. Defaults to False.
            use_multithreading (bool): Whether to use multithreading for scanning. Defaults to False.

        Returns:
            List[dict]: A list of dictionaries, each containing file path and its matches (if any).

        Raises:
            FileNotFoundError: If the directory to scan is not found.
            PermissionError: If there is a permission error accessing the directory.
            ValueError: If the directory is not actually a directory.
        """
        logger.info(
            f"Scanning directory: {directory_path}, recursive: {recursive}, multithreading: {use_multithreading}"
        )
        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        if not os.access(directory_path, os.R_OK):
            logger.error(f"Permission error accessing directory: {directory_path}")
            raise PermissionError(
                f"Permission error accessing directory: {directory_path}"
            )
        if not os.path.isdir(directory_path):
            logger.error(f"Path is not a directory: {directory_path}")
            raise ValueError(f"Path is not a directory: {directory_path}")

        results = []
        files_to_scan = []

        if recursive:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.splitext(file)[1].lower() in INTERESTING_EXTENSIONS:
                        files_to_scan.append(file_path)
        else:
            for file in os.listdir(directory_path):
                file_path = os.path.join(directory_path, file)
                if (
                    os.path.isfile(file_path)
                    and os.path.splitext(file)[1].lower() in INTERESTING_EXTENSIONS
                ):
                    files_to_scan.append(file_path)

        if use_multithreading:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(self.scan_file_and_format_result, file_path)
                    for file_path in files_to_scan
                ]
                for future in futures:
                    result = future.result()
                    if result:
                        results.append(result)
        else:
            for file_path in files_to_scan:
                result = self.scan_file_and_format_result(file_path)
                if result:
                    results.append(result)

        logger.info(
            f"Directory scan completed in: {directory_path}, found matches in {len(results)} files."
        )
        return results

    def scan_file_and_format_result(self, file_path: str) -> Optional[dict]:
        """
        Scans a file and formats the result into a dictionary.

        Args:
            file_path (str): Path to the file to scan.

        Returns:
            Optional[dict]: A dictionary containing file path and matches, or None if no matches.
        """
        try:
            matches = self.scan_file(file_path)
            if matches:
                formatted_matches = []
                for match in matches:
                    formatted_matches.append(
                        {
                            "rule": match.rule,
                            "tags": match.tags,
                            "namespace": match.namespace,
                            "meta": match.meta,
                            "strings": [
                                {
                                    "identifier": s.identifier,
                                }
                                for s in match.strings
                            ],
                        }
                    )
                return {"file_path": file_path, "matches": formatted_matches}
        except (FileNotFoundError, PermissionError, yara.Error) as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return None
        return None


class ResultHandler:
    """
    Handles and outputs the results of YARA scans.
    """

    def __init__(self, verbose: bool = False) -> None:
        """
        Initializes the ResultHandler.

        Args:
            verbose (bool): Enables verbose output to console. Defaults to False.
        """
        self.verbose = verbose

    def output_results(self, scan_results: List[dict]) -> None:
        """
        Outputs the scan results to the console and logs.

        Args:
            scan_results (List[dict]): List of scan result dictionaries.
        """
        if not scan_results:
            logger.info("No YARA matches found in scanned targets.")
            if self.verbose:
                print("No YARA matches found.")
            return

        logger.info(f"Total YARA matches found in {len(scan_results)} files.")
        if self.verbose:
            print("\n--- YARA Scan Results ---")

        for result in scan_results:
            file_path = result["file_path"]
            matches = result["matches"]
            log_message = f"Matches found in: {file_path}"
            logger.warning(log_message)
            if self.verbose:
                print(f"\nFile: {file_path}")
                print("Matches:")
            for match_data in matches:
                rule_name = match_data["rule"]
                tags = match_data["tags"]
                namespace = match_data["namespace"]
                meta = match_data["meta"]
                strings = match_data["strings"]

                match_output = f"  Rule: {rule_name}, Namespace: {namespace}, Tags: {tags}, Meta: {meta}"
                logger.warning(match_output)
                if self.verbose:
                    print(match_output)
                    if strings:
                        print("  Strings:")
                        for s in strings:
                            string_output = f"    Identifier: {s['identifier']}"
                            logger.debug(string_output)
                            if self.verbose:
                                print(string_output)
            if self.verbose:
                print("-" * 30)


def main() -> None:
    """
    Main function to set up argument parsing, load rules, perform scans, and handle results.
    """
    parser = argparse.ArgumentParser(
        description="Enhanced YARA Scanner with flexible input and output."
    )
    parser.add_argument("rules_path", help="Path to YARA rules file or directory")
    parser.add_argument(
        "target_path", help="Path to file, directory, or 'memory' to scan"
    )
    parser.add_argument(
        "-r", "--recursive", action="store_true", help="Scan directories recursively"
    )
    parser.add_argument(
        "-m",
        "--memory",
        action="store_true",
        help="Treat target as memory buffer (provide buffer data via stdin)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-t",
        "--threads",
        action="store_true",
        help="Use multithreading for directory scanning (improves speed on large directories)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level",
    )
    parser.add_argument(
        "--pyi",
        "--pyinstxtractor",
        action="store_true",
        help="Extract the compiled by PyInstaller .exe with Pyinstxtractor before scanning.",
    )

    args = parser.parse_args()

    logger.setLevel(args.log_level.upper())

    rule_loader = RuleLoader()
    try:
        if os.path.isfile(args.rules_path):
            rule_loader.load_rules_from_file(args.rules_path)
        elif os.path.isdir(args.rules_path):
            rule_loader.load_rules_from_directory(args.rules_path)
        else:
            logger.error(
                f"Invalid rules path: {args.rules_path}. Path must be a file or directory."
            )
            print(
                f"Error: Invalid rules path. Path must be a file or directory: {args.rules_path}"
            )
            return
    except (FileNotFoundError, yara.SyntaxError, yara.Error, ValueError) as e:
        logger.error(f"Rule loading failed: {e}")
        print(f"Error loading rules: {e}")
        return

    try:
        scanner = Scanner(rule_loader.get_rules())
        result_handler = ResultHandler(verbose=args.verbose)
        scan_results = []

        target_path_to_scan = args.target_path

        if args.target_path.lower().endswith(".exe") and args.pyi:
            if not os.path.exists("pyinstxtractor.py"):
                logger.error(
                    "pyinstxtractor.py not found in the same directory. Please ensure it is present or provide the correct path."
                )
                print(
                    "Error: pyinstxtractor.py not found. Ensure it's in the same directory."
                )
                return

            logger.info(
                f"Attempting to extract {args.target_path} using pyinstxtractor.py..."
            )
            try:
                command = ["python", "pyinstxtractor.py", args.target_path]
                process = subprocess.run(
                    command, capture_output=True, text=True, check=True
                )
                logger.info(
                    f"pyinstxtractor.py executed successfully for {args.target_path}. Output:\n{process.stdout}\nErrors:\n{process.stderr}"
                )

                extracted_dir = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    f"{os.path.splitext(os.path.basename(args.target_path))[0]}.exe_extracted",
                )
                logger.debug(f"Constructed extracted directory path: {extracted_dir}")
                logger.debug(f"Checking if extracted directory exists: {extracted_dir}")

                if os.path.isdir(extracted_dir):
                    logger.debug(f"Extracted directory EXISTS: {extracted_dir}")
                    target_path_to_scan = extracted_dir
                    logger.info(f"Scanning extracted directory: {extracted_dir}")
                else:
                    logger.debug(f"Extracted directory DOES NOT EXIST: {extracted_dir}")
                    logger.warning(
                        f"Extraction directory not found after running pyinstxtractor.py, scanning original EXE: {args.target_path}"
                    )

            except subprocess.CalledProcessError as e:
                logger.error(
                    f"Error running pyinstxtractor.py on {args.target_path}. Please ensure pyinstxtractor.py is correctly configured and works. Error: {e.stderr}"
                )
                print(f"Error running pyinstxtractor.py: {e.stderr}")
                return
            except FileNotFoundError:
                logger.error(
                    "Python executable not found. Ensure Python is in your PATH to run pyinstxtractor.py"
                )
                print("Error: Python not found in PATH. Cannot run pyinstxtractor.py")
                return

        if args.memory:
            memory_data = input(
                "Enter memory buffer data to scan (or pipe in): "
            ).encode("latin1")
            matches = scanner.scan_memory(memory_data)
            if matches:
                scan_results.append(
                    {"file_path": "<memory buffer>", "matches": matches}
                )
        elif os.path.isdir(target_path_to_scan):
            scan_results = scanner.scan_directory(
                target_path_to_scan,
                recursive=args.recursive,
                use_multithreading=args.threads,
            )
        elif os.path.isfile(target_path_to_scan):
            file_matches_result = scanner.scan_file_and_format_result(
                target_path_to_scan
            )
            if file_matches_result:
                scan_results.append(file_matches_result)
        else:
            logger.error(
                f"Invalid target path: {args.target_path}. Path must be a file, directory, or use --memory."
            )
            print(
                f"Error: Invalid target path. Path must be a file or directory, or use --memory option: {args.target_path}"
            )
            return

        result_handler.output_results(scan_results)

    except (FileNotFoundError, PermissionError, ValueError, TypeError, yara.Error) as e:
        logger.error(f"Scanning process failed: {e}")
        print(f"Scanning error: {e}")
        return

    logger.info("YARA scanning process completed.")


if __name__ == "__main__":
    main()
