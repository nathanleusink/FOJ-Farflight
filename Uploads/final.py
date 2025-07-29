#!/usr/bin/env python3
# create_hello.py - Creates a file named 'hello.txt' with a greeting.

def main():
    file_path = "hello.txt"
    content = "Hello, Linux!\n"
    
    try:
        with open(file_path, "w") as file:
            file.write(content)
        print(f"✅ Successfully created '{file_path}' with the message: '{content.strip()}'")
    except Exception as e:
        print(f"❌ Failed to create file: {e}")

if __name__ == "__main__":
    main()

