import random
import sys
from pathlib import Path
import subprocess
import time


TOP_PATH_1 = "../src/ghidra/Extensions"
TOP_PATH_2 = "../src/ghidra/Features"
TOP_PATH_3 = "../src/ghidra/framework"


def main() -> int:
    path1 = Path(TOP_PATH_1).absolute()
    path1_list = list(path1.glob("**/*.java"))
    path2 = Path(TOP_PATH_2).absolute()
    path2_list = list(path2.glob("**/*.java"))
    path2_list_2 = list(path2.glob("**/*.h"))
    path2_list_3 = list(path2.glob("**/*.c"))
    path2_list_4 = list(path2.glob("**/*.cpp"))
    full_path_2_list = path2_list + path2_list_2 + path2_list_3 + path2_list_4
    path3 = Path(TOP_PATH_3).absolute()
    path3_list = list(path3.glob("**/*.java"))
    path3_list_2 = list(path3.glob("**/*.h"))
    path3_list_3 = list(path3.glob("**/*.c"))
    path3_list_4 = list(path3.glob("**/*.cpp"))
    full_path3_list = path3_list + path3_list_2 + path3_list_3 + path3_list_4
    all_paths_list = path1_list + full_path_2_list + full_path3_list

    for path in all_paths_list:
        print(path.name)

        subprocess.call(
            f'gh issue create -t "port {path.name} to rust" -b "todo"', shell=True
        )

        sleep_time = float(random.randrange(10,30,1))/10
        print(f"sleeping for {sleep_time} secs")
        time.sleep(sleep_time)

    return 0


if __name__ == "__main__":
    sys.exit(main())
