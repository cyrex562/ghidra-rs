import os
import sys

def list_java_files(root_dir):
    java_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".java"):
                # Get relative path from root_dir
                rel_path = os.path.relpath(os.path.join(root, file), root_dir)
                java_files.append(rel_path)
    return sorted(java_files)

def main():
    orig_src = "orig_src"
    if not os.path.exists(orig_src):
        print(f"Error: {orig_src} directory not found.")
        sys.exit(1)

    print(f"Listing Java files in {orig_src}:")
    files = list_java_files(orig_src)
    for f in files:
        # For now, just print the file path.
        # Later, we can check if a corresponding .rs file exists in ghidra-rs/src
        print(f)

    print(f"\nTotal Java files: {len(files)}")

if __name__ == "__main__":
    main()
