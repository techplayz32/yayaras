# Yet Another YARA Scanner

Scanner for Simple Indicators and YARA rules, makes job gets easier. This project aimed on making scanning malware easier and researching new malware families, since there are many of new script kiddies around.

## Prerequirements

I suggest to use [UV](https://github.com/astral-sh/uv) for managing the project and adding own changes.

For the Python, it is recommended that version higher than `3.12`.

As for the dependencies, use `uv pip install/pip(x) install -r requirements.txt` to install dependencies from `requirements.txt`.

## Usage

The script can be run by passing the `index.yar` or specific rule from folder `rules` and filepath `malware.exe` as the arguments.

```bash
yayaras.py rules_path target_path
```

## Dependencies

```pip
argparse>=1.4.0
black>=25.1.0
logging>=0.4.9.6
yara-python>=4.5.1
```

## License

YAYARAS is open-source software licensed under the **GNU General Public License v3 (GPLv3)**. See the full [LICENSE](LICENSE) file for details.

This project uses code/executable from other open-source projects with their own licenses:

* **YAYARAS (project as a whole) and [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) (if used):** GPLv3 - [LICENSE](LICENSE)
* **[YARA](https://github.com/virustotal/yara):** BSD 3-Clause License - [LICENSE-BSD-3-Clause.txt](LICENSE-BSD-3-Clause.txt)

You should know and, do before changing code in YAYARAS that:

* YAYARAS is GPLv3 licensed. You can find the full GPLv3 license in the `LICENSE` file.
* YAYARAS uses YARA, which is licensed under the BSD 3-Clause License. The full BSD 3-Clause license is in `LICENSE-BSD-3-Clause.txt`.  **Please ensure you comply with the BSD 3-Clause license when using YARA.**

**For complete licensing terms, please refer to the full license files: [LICENSE](LICENSE) and [LICENSE-BSD-3-Clause.txt](LICENSE-BSD-3-Clause.txt).**
