# pa-permission-entropy-analyzer
Calculates the entropy of permission settings across a system or directory, highlighting areas with unusually high or low permission complexity, which could indicate misconfigurations or vulnerabilities. Uses the `os` and `math` standard library modules, and `rich` for the table. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-entropy-analyzer`

## Usage
`python3 main.py [path] [params]`

## Parameters
- `-h`: Show help message and exit
- `-e`: Exclude files/directories matching this pattern (glob).
- `-r`: Recursively analyze subdirectories.
- `-t`: Threshold, in bits of per file mode surprise, for highlighting high entropy files. (Default: 0.0)
- `-q`: Suppress informational output.
- `-v`: Enable verbose logging.

## Behavior notes
- The overall Permission Entropy is the Shannon entropy of the distribution of permission modes in the analyzed set.
- The per file figure, headed Surprise (bits), is the self-information of that file's mode under the same distribution: a mode every file shares scores 0, and a rare mode scores high. Its average over the set equals the overall entropy. Files whose surprise exceeds a positive `--threshold` are listed under High Entropy Files. Earlier versions computed the entropy of a one element set for each file, which is always 0.0, so the highlighting could never fire.
- A run that analyzes no files, for example over an empty directory, prints that no analysis was performed and exits 1. Files whose permissions cannot be read are counted and reported as skipped.

## License
Copyright (c) ShadowStrikeHQ
